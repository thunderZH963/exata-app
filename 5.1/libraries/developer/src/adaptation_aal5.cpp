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
// PROTOCOL     :: AAL5.
// LAYER        :: ADAPTATION.
// REFERENCES   ::
//              RFC: 2225 for Classical IP and ARP over ATM
//              RFC: 2684 for Multi-protocol Encapsulation over
//                 ATM Adaptation Layer 5
//              ATM Forum Addressing Specification:
//              Reference Guide AF-RA-0106.000
// COMMENTS     :: None
// **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "partition.h"
#include "mac_link.h"
#include "network_ip.h"
#include "transport_udp.h"
#include "transport_tcp_hdr.h"

#include "adaptation_aal5.h"
#include "adaptation_saal.h"
#include "route_atm.h"
#include "atm.h"
#include "atm_layer2.h"
#include "mac_arp.h"
#include "atm_logical_subnet.h"

#include "random.h"

#define DEBUG 0


// /**
// FUNCTION    :: Aal5PrintTransTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: To printf ATM Trans table
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void Aal5PrintTransTable(Node* node)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);

    AtmTransTable* transTable = &aal5Data->transTable;
    AtmTransTableRow* row;
    unsigned int i;

    if (transTable->numRows != 0)
    {
        printf(" # %u has Translation Table: \n", node->nodeId);
        printf("--------------------------------------------\n");
        printf(" VCI     VPI    finalVCI  finalVPI outIntf \n");

        for (i = 0; i < transTable->numRows; i++)
        {
            row = &transTable->row[i];

            printf(" %d    %d       %d        %d        %d \n",
                row->VCI, row->VPI, row->VCI, row->finalVPI,
                row->outIntf);
        }
        printf("\n \n");
    }
}


// /**
// FUNCTION    :: Aal5PrintAddrInfoTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Print AddrInfo table
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + intf       : int : Interface
// RETURN       : void : None
// **/
void Aal5PrintAddrInfoTable(Node* node, int intf)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    Aal5InterfaceData* atmIntf = aal5Data->myIntfData;

    Aal5AddrInfoTable* addrInfoTable = &atmIntf[intf].addrInfoTable;
    Aal5AddrInfoTableRow* row;
    Aal5AssociatedIPListItem* listItem;
    NodeAddress destIP = 0;

    unsigned int i;

    printf(" Node %u: Address info Table \n", node->nodeId);
    printf("-----------------------------------------\n");
    printf("logicalIp         AtmAddr      destIp\n");

    for (i = 0 ; i< addrInfoTable->numRows ; i++)
    {
        row = &addrInfoTable->row[i];

        if (row->associatedIPList->size)
        {
            listItem = (Aal5AssociatedIPListItem*)row->
                associatedIPList->first->data;
            destIP = listItem->ipAddr.interfaceAddr.ipv4;
        }

        printf("%x         %d|%d       %x \n",
            row->memberlogicalIP.interfaceAddr.ipv4,
            row->memberATMAddress.ESI_pt1,
            row->memberATMAddress.ESI_pt2,
            destIP);
    }
}


// /**
// FUNCTION    :: Aal5PrintFwdTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Print Forwarding table
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void Aal5PrintFwdTable(Node* node)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    Aal5FwdTable* frwdTable = &aal5Data->fwdTable;
    Aal5FwdTableRow* row;

    unsigned int i;

    if (frwdTable->numRows != 0)
    {
        printf(" # %u has Fwd Table: \n", node->nodeId);
        printf("------------------------------------\n");
        printf("Destn    outIntf    nextNode\n");
        for (i = 0; i < frwdTable->numRows; i++)
        {
            row = &frwdTable->row[i];

            printf(" %u|%d     %d       %u|%d  \n",
                row->destAtmAddr.ESI_pt1,
                row->destAtmAddr.ESI_pt2,
                row->outIntf,
                row->nextAtmNode.ESI_pt1,
                row->nextAtmNode.ESI_pt2);
        }
        printf("\n \n");
    }
}


// /**
// FUNCTION    :: Aal5PrintConncTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: To print Aal5 connection table
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void Aal5PrintConncTable(Node* node)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);

    Aal5ConncTable* conncTable = &aal5Data->conncTable;
    Aal5ConncTableRow* row;
    unsigned int i;
    char clock[MAX_STRING_LENGTH] = {0};

    if (conncTable->numRows != 0)
    {
        printf("____________________________________________________\n");
        printf(" # %u has Connection Table: \n", node->nodeId);
        printf("Src   Dst   SPort  Dport  VCI   VPI  status lastPkt\n");
        for (i = 0; i < conncTable->numRows; i++)
        {
            row = &conncTable->row[i];
            TIME_PrintClockInSecond(row->lastPktRecvdTime, clock);

            printf(" %x   %x   %d    %d    %d   %d   %d   %s\n",
                row->appSrcAddr.interfaceAddr.ipv4,
                row->appDstAddr.interfaceAddr.ipv4,
                row->appSrcPort,
                row->appDstPort,
                row->VCI,
                row->VPI,
                row->saalStatus,
                clock);
        }
        printf("____________________________________________________\n");
        printf("\n \n");
    }
}


// /**
// FUNCTION    :: AalGetPtrForThisAtmNode
// LAYER       :: Adaptation Layer
// PURPOSE     :: Get the related adaptation layer Ptr for this ATM Node
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// RETURN       : Aal5Data* : Pointer to AAL5 data.
// **/
Aal5Data* AalGetPtrForThisAtmNode(Node* node)
{
   return (Aal5Data*)(node->adaptationData.adaptationVar);
}


// /**
// FUNCTION    :: AalGetOutIntfAndNextHopForDest
// LAYER       :: Adaptation Layer
// PURPOSE     :: Get the outgoing Interface & the next op from
//                the forwarding table of the node
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + destAtmAddr : AtmAddress* : Pointer to Destination Address
// + outIntf    : int* : Pointer to outgoing interface index.
// + nextHop    : AtmAddress* : Pointer to nextHop
// RETURN       : void : None
// **/
void AalGetOutIntfAndNextHopForDest(
    Node* node,
    AtmAddress* destAtmAddr,
    int* outIntf,
    AtmAddress* nextHop)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    Aal5FwdTable* frwdTable = &aal5Data->fwdTable;
    Aal5FwdTableRow* row;
    unsigned int i;

    // TBD: this should be done by PNNI
    // at present it is done by STATIC-ATM routing
    // Search route for corresponding AtmAddress
    // from each row of FWD table

    if (frwdTable->numRows != 0)
    {
        for (i = 0; i < frwdTable->numRows; i++)
        {
            row = &frwdTable->row[i];

            if (DEBUG)
            {
                printf("%u searching for dest %u \n",
                    node->nodeId,
                    destAtmAddr->ESI_pt1);
                printf(" available dest %u \n",
                    row->destAtmAddr.ESI_pt1);
            }

            // search for matching ATM Addr
            if (row->destAtmAddr.ESI_pt1 == destAtmAddr->ESI_pt1)
            {
                //retrive outIntf & nextHop

                if (DEBUG)
                {
                    printf(" Node %u got outIntf %d nextHop %x\n",
                        node->nodeId, row->outIntf,
                        row->nextAtmNode.ESI_pt1);
                }

                *outIntf = row->outIntf;

                // Assuming next elemnt is an ATM Node
                memcpy(nextHop,
                    &row->nextAtmNode,
                     sizeof(AtmAddress));

                return;
            }
        }
    }

    *outIntf =  SAAL_INVALID_INTERFACE;
    memset(nextHop, 0, sizeof(AtmAddress));
}


// /**
// FUNCTION    :: Aal5GenerateNewConnectionId
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set value for VPI & VCI for this application
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + appSrcAddr : NodeAddress : Source address of application.
// + appDstAddr : NodeAddress : Destination address of application.
// + appSrcPort : unsigned short : Source port of application.
// + conncId : unsigned short* : Connection ID
// RETURN       : void : None
// **/
void Aal5GenerateNewConnectionId(Node* node,
                                 NodeAddress appSrcAddr,
                                 NodeAddress appDstAddr,
                                 unsigned short appSrcPort,
                                 unsigned short appDstPort,
                                 unsigned short* conncId)
{
    RandomSeed seed;   /* seed for random number generator */
    unsigned short tempSeed;

    seed[0] = appSrcPort;
    seed[1] = (unsigned short)appSrcAddr;
    seed[2] = (unsigned short)appDstAddr;

    RandomDistribution<Int32> randomLong;

    randomLong.setSeed(seed);

    randomLong.setDistributionUniform(ATM_DATA_MIN_VCI, ATM_DATA_MAX_VCI);
    tempSeed = (unsigned short)randomLong.getRandomNumber();

    seed[0] = tempSeed;
    seed[1] = appDstPort;
    seed[2] = (unsigned short)(appSrcAddr >> 16);

    // The connection Id is generated using VPI & VCI,
    // This unique combination can identify one Connc/appl.
    // It is a number lies between 0 to 65535.
    // Among which 0 to 32 is reserved.

    *conncId = (unsigned short)randomLong.getRandomNumber(seed);
}


// /**
// FUNCTION    :: AalCheckIfItIsInAttachedNetwork
// LAYER       :: Adaptation Layer
// PURPOSE     :: Check If the dest and the node is in same network
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + addrPtr    : AtmAddress* : Pointer to ATM address
// RETURN       : BOOL
// **/
BOOL AalCheckIfItIsInAttachedNetwork(Node* node, AtmAddress* addrPtr)
{
    Aal5Data*   aal5Data;
    int i;

    aal5Data = AalGetPtrForThisAtmNode(node);

    if (addrPtr->AFI == 0)
    {
        // ATM addr Ptr is not specified here
        return FALSE;
    }

    for (i = 0; i < node->numAtmInterfaces; i++)
    {
        if ((aal5Data->myIntfData[i].atmIntfAddr.ICD == addrPtr->ICD)
            && (aal5Data->myIntfData[i].atmIntfAddr.aid_pt1
                == addrPtr->aid_pt1)
            && (aal5Data->myIntfData[i].atmIntfAddr.aid_pt2
                == addrPtr->aid_pt2))
        {
            return TRUE;
        }
    }
    return FALSE;
}


// /**
// FUNCTION    :: Aal5InitInterface
// LAYER       :: Adaptation Layer
// PURPOSE     :: Initialize the parametrs associated
//                with each ATM Interface
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + nodeInput  : const NodeInput * : Pointer to config file.
// + interfaceIndex : int : Interface index.
// RETURN       : void : None
// **/
void Aal5InitInterface(Node *node,
                       const NodeInput *nodeInput,
                       int interfaceIndex)
{
    BOOL retVal;
    Aal5InterfaceData* atmIntf;
    Address thisIntfAddr;

    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);
    AtmLayer2Data* atmData = Atm_Layer2GetAtmData(node, interfaceIndex);

    if (DEBUG)
    {
        printf(" #%u AAL5 init-update here for intf %d\n",
            node->nodeId, interfaceIndex);
    }

    // Set ATM address for this interface
    atmIntf = aal5DataPtr->myIntfData;

    thisIntfAddr = MAPPING_GetInterfaceAddressForInterface(
        node, node->nodeId, NETWORK_ATM, interfaceIndex);

    memcpy(&atmIntf[interfaceIndex].atmIntfAddr,
        &thisIntfAddr.interfaceAddr.atm,
        sizeof(AtmAddress));

    // Set Bandwidth related info
    atmIntf[interfaceIndex].totalBandwidth = atmData->bandwidth;
    atmIntf[interfaceIndex].propDelay = atmData->propDelay;

    // set Other interface Parameter
    atmIntf[interfaceIndex].intfId = interfaceIndex;

    // If the node is an END system
    // it maintained connection related information

    if (node->adaptationData.endSystem)
    {
        // Set Connection timeout Time &
        // Connection table Refresh time

        IO_ReadTime(
            node->nodeId,
            &(atmIntf[interfaceIndex].atmIntfAddr),
            nodeInput,
            "ATM-CONNECTION-REFRESH-TIME",
            &retVal,
            &(atmIntf[interfaceIndex].conncRefreshTime));

        if (retVal == FALSE)
        {
            printf("Node %u,connection refresh time not avilable \n",
                node->nodeId);

            atmIntf[interfaceIndex].conncRefreshTime =
                ATM_DEFAULT_CONNECTION_REFRESH_TIME;
        }

        IO_ReadTime(
            node->nodeId,
            &(atmIntf[interfaceIndex].atmIntfAddr),
            nodeInput,
            "ATM-CONNECTION-TIMEOUT-TIME",
            &retVal,
            &(atmIntf[interfaceIndex].conncTimeoutTime));

        if (retVal == FALSE)
        {
            atmIntf[interfaceIndex].conncTimeoutTime =
                ATM_DEFAULT_CONNECTION_TIMEOUT_TIME;
        }


    }
}


// /**
// NAME        :: Aal5UpdateAddressInfoTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Update address table with information
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + intfId     : int : Interface Identifier.
// + destAtmAddr: AtmAddress* : Pointer to destination address.
// + destIpAddr : Address* : Pointer to destination IP address.
// RETURN       : void : None.
// **/
void Aal5UpdateAddressInfoTable(
    Node *node,
    int intfId,
    AtmAddress* destAtmAddr,
    Address* destIpAddr)
{
    unsigned int i;

    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    Aal5InterfaceData* atmIntf = aal5Data->myIntfData;

    Aal5AddrInfoTable* addrInfoTable
        = &atmIntf[intfId].addrInfoTable;

    Aal5AddrInfoTableRow* row;

    // presently maintained by all end-system
    // for each logical SUBNET connected to it

    for (i = 0; i < addrInfoTable->numRows; i++)
    {
        row = &addrInfoTable->row[i];

        if ((row->memberATMAddress.ESI_pt1 == destAtmAddr->ESI_pt1)
            &&(row->memberATMAddress.ESI_pt2 == destAtmAddr->ESI_pt2))
        {
            Aal5AssociatedIPListItem* newEntry =
                (Aal5AssociatedIPListItem*)MEM_malloc
                (sizeof(Aal5AssociatedIPListItem));

            newEntry->ipAddr.networkType
                = destIpAddr->networkType;

            newEntry->ipAddr.interfaceAddr.ipv4
                = destIpAddr->interfaceAddr.ipv4;

            //update associatedIPList
            ListInsert(node,
                row->associatedIPList,
                0,
                (void*) newEntry);

            return;
        }
    }

    if (DEBUG)
    {
        Aal5PrintAddrInfoTable(node, intfId);
    }
}


// /**
// NAME        :: Aal5AddressInfoTableInit
// LAYER       :: Adaptation Layer
// PURPOSE     :: Handling all initializations needed by ATM-ARP.
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + intfId     : int : Interface Identifier.
// RETURN       : void : None.
// **/
void Aal5AddressInfoTableInit(Node *node, int intfId)
{
    int i;
    NodeAddress memberLogicalIP;
    AtmAddress memberAtmAddr;
    Address recvdAddr;

    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    Aal5InterfaceData* atmIntf = aal5Data->myIntfData;

    Aal5AddrInfoTable* addrInfoTable
        = &atmIntf[intfId].addrInfoTable;

    Aal5AddrInfoTableRow* row;
    const LogicalSubnet* logicalSubnet = AtmGetLogicalSubnetFromNodeId(
                                            node, node->nodeId, intfId);
    unsigned char* HWAddrPtr =
        (unsigned char*)MEM_malloc(sizeof(unsigned char) * 6);

    // Init Address Info table
    // presently maintained by all end-system
    // but it should be mintained by ARP server
    // for each logical SUBNET connected to it

    unsigned int extraRows = 0;

    if (AAL_INITIAL_TABLE_SIZE < logicalSubnet->numMember)
        extraRows = logicalSubnet->numMember - AAL_INITIAL_TABLE_SIZE;

    atmIntf[intfId].addrInfoTable.numRows = 0;
    atmIntf[intfId].addrInfoTable.allottedNumRow
        = AAL_INITIAL_TABLE_SIZE + extraRows;

    atmIntf[intfId].addrInfoTable.row
        = (Aal5AddrInfoTableRow*)MEM_malloc
        (sizeof(Aal5AddrInfoTableRow) * (AAL_INITIAL_TABLE_SIZE +extraRows));

     memset(
          atmIntf[intfId].addrInfoTable.row,
          0,
          sizeof(Aal5AddrInfoTableRow) *(AAL_INITIAL_TABLE_SIZE +extraRows));

    for (i = 0 ; i< logicalSubnet->numMember; i++)
    {
        BOOL hwAddrFound;

        // Read the logical IP of that member
        memberLogicalIP = AtmGetLogicalIPAddressFromNodeId(
            node,
            (logicalSubnet->member)[i].nodeId,
            (logicalSubnet->member)[i].relativeIndex);

        if (DEBUG)
        {
            printf ("Node %u:logical mbr %u intf %d \n",
                node->nodeId,
                (logicalSubnet->member)[i].nodeId,
                (logicalSubnet->member)[i].relativeIndex);

            printf(" Associted logical addr %x \n", memberLogicalIP);
        }

        // Read the Domain Specific part of the ATM Addr
        // of each member
        recvdAddr =
            MAPPING_GetInterfaceAddressForInterface(
            node,
            (logicalSubnet->member)[i].nodeId,
            NETWORK_ATM,
            (logicalSubnet->member)[i].relativeIndex);

        memcpy(&memberAtmAddr,
            &recvdAddr.interfaceAddr.atm,
            sizeof(AtmAddress));

        // Read the associated HW Addr from ARP
        hwAddrFound = ArpLookUpHarwareAddress(node,
            memberLogicalIP,
            intfId,
            ARP_HRD_ATM,
            HWAddrPtr);

        // if hwaddr is not found, create is as default
        if (!hwAddrFound)
        {
            memcpy(HWAddrPtr,
                &memberAtmAddr.ESI_pt1,
                sizeof(unsigned char) * 4);

            memcpy(HWAddrPtr + (sizeof(unsigned char) * 4),
                &memberAtmAddr.ESI_pt2,
                sizeof(unsigned char) * 2);
        }

        //Add the HW part in this ATM Address

        memcpy(&memberAtmAddr.deviceAddr_pt1,
            HWAddrPtr,
            sizeof(unsigned char) * 4);

        memcpy(&memberAtmAddr.deviceAddr_pt2,
            HWAddrPtr + (sizeof(unsigned char) * 4),
            sizeof(unsigned char) * 2);

        // Finally update Address info table with this information
        row = &addrInfoTable->row[addrInfoTable->numRows];

        // set member logical IP Info
        row->memberlogicalIP.networkType = NETWORK_IPV4;
        row->memberlogicalIP.interfaceAddr.ipv4 = memberLogicalIP;

        // set member ATM Address
        memcpy(&row->memberATMAddress,
            &memberAtmAddr,
            sizeof(AtmAddress));

        // Init gateway list
        ListInit(node, &row->associatedIPList);

        addrInfoTable->numRows++;
    }

    if (DEBUG)
    {
        Aal5PrintAddrInfoTable(node, intfId);
    }
}


// /**
// NAME        :: Aal5InitFwdTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Initialize the parameter associated
//                with Atm forwarding Table
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None.
// **/
void Aal5InitFwdTable(Node* node)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);

    aal5Data->fwdTable.numRows = 0;
    aal5Data->fwdTable.allottedNumRow = AAL_INITIAL_TABLE_SIZE;
    aal5Data->fwdTable.row = (Aal5FwdTableRow*)MEM_malloc
        (sizeof(Aal5FwdTableRow) * AAL_INITIAL_TABLE_SIZE);

    memset(aal5Data->fwdTable.row, 0,
        sizeof(Aal5FwdTableRow) * AAL_INITIAL_TABLE_SIZE);
}


// /**
// NAME        :: Aal5InitTransTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Initialize Atm Translation Table
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None.
// **/
void Aal5InitTransTable(Node* node)
{
    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    aal5DataPtr->transTable.numRows = 0;
    aal5DataPtr->transTable.allottedNumRow = AAL_INITIAL_TABLE_SIZE;
    aal5DataPtr->transTable.row = (AtmTransTableRow*)MEM_malloc
        (sizeof(AtmTransTableRow) * AAL_INITIAL_TABLE_SIZE);

    memset(aal5DataPtr->transTable.row, 0,
        sizeof(AtmTransTableRow) * AAL_INITIAL_TABLE_SIZE);
}


// /**
// NAME        :: Aal5InitConncTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Initialize the parameter associated with Connection Table
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None.
// **/
void Aal5InitConncTable(Node* node)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);

    aal5Data->conncTable.numRows = 0;
    aal5Data->conncTable.allottedNumRow = AAL_INITIAL_TABLE_SIZE;
    aal5Data->conncTable.row = (Aal5ConncTableRow*)MEM_malloc
        (sizeof(Aal5ConncTableRow) * AAL_INITIAL_TABLE_SIZE);

    memset(aal5Data->conncTable.row, 0,
        sizeof(Aal5ConncTableRow) * AAL_INITIAL_TABLE_SIZE);
}


// /**
// FUNCTION    :: Aal5UpdateFwdTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Create/Modify entry in Forwarding table
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + outIntf    : unsigned int : Outgoing Interface
// + destAtmAddr: AtmAddress* : Pointer to destination address
// + nextAtmNode: AtmAddress* : Pointer to next ATM node
// RETURN       : void : None
// **/
void Aal5UpdateFwdTable(
    Node* node,
    unsigned int outIntf,
    AtmAddress* destAtmAddr,
    AtmAddress* nextAtmNode)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);

    Aal5FwdTable* frwdTable = &aal5Data->fwdTable;
    Aal5FwdTableRow* newRow;
    unsigned int i;


    for (i = 0 ; i< frwdTable->numRows ; i++)
    {
        newRow = &frwdTable->row[i];

        if ((newRow->destAtmAddr.ESI_pt1 == destAtmAddr->ESI_pt1)
            && (newRow->destAtmAddr.ESI_pt2 == destAtmAddr->ESI_pt2))
        {
            // Modify the existing route information
            // outIntf & nextHop are set
            newRow->outIntf = outIntf;

            memcpy(&newRow->nextAtmNode,
                nextAtmNode,
                sizeof(AtmAddress));

            return;
        }
    }

    if (frwdTable->numRows == frwdTable->allottedNumRow)
    {
        Aal5FwdTableRow* oldRow = frwdTable->row;
        int size = 2 * frwdTable->allottedNumRow
                    * sizeof(Aal5FwdTableRow);

        // Double forwarding table size
        frwdTable->row = (Aal5FwdTableRow*) MEM_malloc(size);

        for (i = 0; i < frwdTable->numRows; i++)
        {
            frwdTable->row[i] = oldRow[i];
        }

        MEM_free(oldRow);

        // Update table size
        frwdTable->allottedNumRow *= 2;
    }   // if table is filled


    newRow = &frwdTable->row[i];

    // Insert new row
    newRow->outIntf = outIntf;

    // copy Dest Address
    memcpy(&newRow->destAtmAddr,
        destAtmAddr,
        sizeof(AtmAddress));

    // copy nextAtm Node
    memcpy(&newRow->nextAtmNode,
                nextAtmNode,
                sizeof(AtmAddress));

    frwdTable->numRows++;

    if (DEBUG)
    {
        Aal5PrintFwdTable(node);
        printf(" \n \n");
    }
}


// /**
// FUNCTION    :: Aal5UpdateTransTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Create/Modify entry in Translation table
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : VCI value
// + VPCI       : unsigned char  : VPCI value
// + finalVPI   : unsigned char  : finalVPI value
// + outIntf    : int : Outgoing Interface
// RETURN       : void : None
// **/
void Aal5UpdateTransTable(
    Node* node,
    unsigned short VCI,
    unsigned char VPI,
    unsigned char finalVPI,
    int outIntf)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);

    AtmTransTable* transTable = &aal5Data->transTable ;
    AtmTransTableRow* newRow = NULL;

    unsigned int i;

    for (i = 0 ; i< transTable->numRows ; i++)
    {
        newRow = &transTable->row[i];

        if (newRow->VCI == VCI)
        {
            // outIntf & nextHop are set
            newRow->outIntf = outIntf;
            newRow->finalVPI = finalVPI;
            newRow->finalVCI = VCI;
            return;
        }
    }

    if (transTable->numRows == transTable->allottedNumRow)
    {
        AtmTransTableRow* oldRow = transTable->row;
        int size = 2 * transTable->allottedNumRow
                    * sizeof(AtmTransTableRow);

        // Double forwarding table size
        transTable->row = (AtmTransTableRow*) MEM_malloc(size);

        for (i = 0; i < transTable->numRows; i++)
        {
            transTable->row[i] = oldRow[i];
        }

        MEM_free(oldRow);

        // Update table size
        transTable->allottedNumRow *= 2;
    }   // if table is filled


    newRow = &transTable->row[i];

    // Insert new row
    newRow->VCI = VCI;
    newRow->VPI = VPI;
    newRow->finalVCI = VCI;
    newRow->finalVPI = finalVPI;
    newRow->outIntf = outIntf;

    transTable->numRows++;

    if (DEBUG)
    {
        printf("%u:NumRows in TRANSLATION table = %d\n",
            node->nodeId, transTable->numRows);
        printf("    Translation Table is updated for VCI %d & VPI %d\n",
            newRow->VCI, newRow->VPI);
        printf("    outIntf %d \n", newRow->outIntf);

        Aal5PrintTransTable(node);
        printf(" \n \n");
    }
}


// /**
// FUNCTION    :: Aal5UpdateConncTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set status for this application
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : VCI value
// + VPI        : unsigned char : VPI value
// + status     : unsigned char : status
// RETURN       : void : None
// **/
void Aal5UpdateConncTable(
    Node* node,
    unsigned short VCI,
    unsigned char VPI,
    unsigned char status)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    Aal5ConncTable* conncTable = &aal5Data->conncTable;
    Aal5ConncTableRow* row;
    unsigned int i;

    if (DEBUG)
    {
        Aal5PrintConncTable(node);
    }

    // Get the matching entry for this application
    for (i = 0; i < conncTable->numRows; i++)
    {
        row = &conncTable->row[i];

        if (row->VCI == VCI)
        {
            // Matching Entry available
            if (DEBUG)
            {
                printf(" Node %u update connc Table with status %d \n",
                    node->nodeId, status);
            }
            row->saalStatus =
                (SaalSignalingStatus)status;
        }
    }

    // no matching entry available
    if (DEBUG)
    {
        printf(" No matching entry available \n");
        Aal5PrintConncTable(node);
    }
}


// /**
// FUNCTION    :: Aal5SearchTransTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Search the Translation Table for matching Entry
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : VCI value
// + VPI        : unsigned char : VPI value
// RETURN       : AtmTransTableRow* : Pointer to ATM Trans-Table row.
// **/
AtmTransTableRow* Aal5SearchTransTable(
    Node* node,
    unsigned short VCI,
    unsigned char VPI)
{
    unsigned int i;
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    AtmTransTable* transTable = &aal5Data->transTable;
    AtmTransTableRow* row = NULL;

    // First set VPI & VPI for this application

    // Then search the Fwd Table for matching entry
    if (transTable->numRows != 0)
    {
        for (i = 0; i < transTable->numRows; i++)
        {
            row = &transTable->row[i];
            if (row->VCI == VCI)
            {
                return row;
            }
        }
    }
    return NULL;
}


// /**
// FUNCTION    :: Aal5SearchForMatchingEntryInConncTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Search the Connection-Table for matching Entry
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + appSrcAddr : Address : Source Address
// + appDstAddr : Address : Destination Address
// + appSrcPort : unsigned short : Source Port
// + appDstPort : unsigned short : Destination port
// RETURN       : Aal5ConncTableRow* : Pointer to Aal5 Connection-Table row.
// **/
Aal5ConncTableRow* Aal5SearchForMatchingEntryInConncTable(
    Node* node,
    Address appSrcAddr,
    Address appDstAddr,
    unsigned short appSrcPort,
    unsigned short appDstPort)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    Aal5ConncTable* conncTable = &aal5Data->conncTable;
    Aal5ConncTableRow* row;
    unsigned int i;
    unsigned short conncId;

    // First set VPI & VPI for this application
    // The connection Id is generated using VPI & VCI,
    // This unique combination can identify one Connc/appl.
    // VCI is a number lies between 0 to 65535.
    // Among which 0 to 32 is reserved.
    // VPI is given to application specific.

    if (DEBUG)
    {
        Aal5PrintConncTable(node);
    }

    // Get the matching entry for this application
    for (i = 0; i < conncTable->numRows; i++)
    {
        row = &conncTable->row[i];

        if ((appSrcAddr.interfaceAddr.ipv4
                == row->appSrcAddr.interfaceAddr.ipv4)
            && (appDstAddr.interfaceAddr.ipv4
                    == row->appDstAddr.interfaceAddr.ipv4)
            && (appSrcPort == row->appSrcPort)
            && (appDstPort == row->appDstPort))
        {
            // Matching Entry available

            // Update last packet received Time
            row->lastPktRecvdTime = node->getNodeTime();

            return row;
        }
    } //end of for

     if (conncTable->numRows == conncTable->allottedNumRow)
      {
        Aal5ConncTableRow* oldRow = conncTable->row;
        int size = 2 * conncTable->allottedNumRow
                    * sizeof(Aal5ConncTableRow);

        // Double forwarding table size
        conncTable->row = (Aal5ConncTableRow*) MEM_malloc(size);

        for (i = 0; i < conncTable->numRows; i++)
        {
            conncTable->row[i] = oldRow[i];
        }

        MEM_free(oldRow);

        // Update table size
        conncTable->allottedNumRow *= 2;
    }   // if table is filled


    // no matching entry available
    // need to built a new One
    row = &conncTable->row[i];

    // Insert new row
    memcpy(&(row->appSrcAddr), &appSrcAddr, sizeof(Address));
    memcpy(&(row->appDstAddr), &appDstAddr, sizeof(Address));
    row->appSrcPort = appSrcPort;
    row->appDstPort = appDstPort;

     // Aal5 Generate New Connection Id
     Aal5GenerateNewConnectionId(node,
         appSrcAddr.interfaceAddr.ipv4,
         appDstAddr.interfaceAddr.ipv4,
         appSrcPort,
         appDstPort,
         &conncId);

    row->VCI = conncId;

    row->VPI = SAAL_INVALID_VPI;

    //set other parameters
    row->saalType = SIGNALING_SVC;
    row->saalStatus = SAAL_NOT_YET_STARTED;
    row->lastPktRecvdTime = node->getNodeTime();

    // If it is SVC periodically refresh connection table

    if (row->saalType == SIGNALING_SVC)
    {
        // A timer is introduced to check timeout
        SaalTimerData* timerInfo;
        Message* timeoutMsg;

        timeoutMsg = MESSAGE_Alloc(node,
            ADAPTATION_LAYER,
            ATM_PROTOCOL_SAAL,
            MSG_ATM_ADAPTATION_SaalTimeoutTimer);

        MESSAGE_InfoAlloc(node, timeoutMsg, sizeof(SaalTimerData));

        timerInfo = (SaalTimerData*) MESSAGE_ReturnInfo(timeoutMsg);

        timerInfo->seqNo = 1 ;
        timerInfo->VCI = row->VCI;
        timerInfo->VPI = row->VPI;

        MESSAGE_Send(node, (Message*)timeoutMsg,
            aal5Data->myIntfData[DEFAULT_INTERFACE].conncRefreshTime);
    }

    conncTable->numRows++;

    if (DEBUG)
    {
        printf("Updated connc Table:     \n");
        Aal5PrintConncTable(node);
    }

    return row;
}


// /**
// FUNCTION    :: Aal5GetAtmAddrAndLogicalIPForDest
// LAYER       :: Adaptation Layer
// PURPOSE     :: AAL5 function to get logical IP address for destination
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + destIP     : Address : Logical Ip Address for destination.
// + atmAddr    : AtmAddress* : Pointer to ATm address.
// RETURN       : void : None
// **/
void Aal5GetAtmAddrAndLogicalIPForDest(
    Node* node,
    Address destIP,
    AtmAddress* atmAddr)
{
    unsigned int i;
    ListItem* item = NULL;
    NodeAddress respLogicalIP;
    Aal5AssociatedIPListItem* itemData;

    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    Aal5InterfaceData* atmIntf = aal5Data->myIntfData;

    // At present it is assumed that there is only one logical subnet
    // consisting of all ATM nodes. Thus same table is maintained
    // for all interface and searching only one will be sufficient,
    // otherwise we need to search for all the associated
    // interface for responsible logical IP

    Aal5AddrInfoTable* addrInfoTable
        = &atmIntf[DEFAULT_INTERFACE].addrInfoTable;

    Aal5AddrInfoTableRow* row = NULL;

    // Search the Addr Table for matching entry
    if (addrInfoTable->numRows == 0)
    {
        // create a default entry
        Aal5AddressInfoTableInit(node, DEFAULT_INTERFACE);
    }

    // Start searching

    for (i = 0; i < addrInfoTable->numRows; i++)
    {
        row = &addrInfoTable->row[i];

        // Assuming all logical IP subnet is an IPv4 network

        //seach associated list
        item = row->associatedIPList->first;

        //check for matching destIP
        while (item)
        {
            itemData = (Aal5AssociatedIPListItem*) item->data;

            if (itemData->ipAddr.networkType == destIP.networkType)
            {
                if (itemData->ipAddr.interfaceAddr.ipv4 ==
                    destIP.interfaceAddr.ipv4)
                {
                    respLogicalIP =
                        row->memberlogicalIP.interfaceAddr.ipv4;

                    // Associated member ATM Address found
                    memcpy(atmAddr,
                        &row->memberATMAddress,
                        sizeof(AtmAddress));

                    return;
                }
            }
            item = item->next;
        }
    }

    memset(atmAddr,0,sizeof(AtmAddress));
}

// /**
// FUNCTION    :: AtmAdaptationLayer5Init
// LAYER       :: Adaptation Layer
// PURPOSE     :: Initializing AAL5 parameter for this node
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + nodeInput  : const NodeInput* : Pointer to config file.
// RETURN       : void : None
// **/
void AtmAdaptationLayer5Init(Node *node,
                             const NodeInput *nodeInput)
{
    BOOL retVal;
    int i;
    char buf[MAX_STRING_LENGTH];
    Aal5Data* aal5DataPtr = (Aal5Data*) MEM_malloc(sizeof(Aal5Data));
    node->adaptationData.adaptationVar = (void*)aal5DataPtr;
    node->adaptationData.adaptationProtocol = ADAPTATION_PROTOCOL_AAL5;

    aal5DataPtr->myIntfData = (Aal5InterfaceData*)
        MEM_malloc(sizeof(Aal5InterfaceData)
            * (node->numAtmInterfaces));

    memset(aal5DataPtr->myIntfData,
        0,
        sizeof(Aal5InterfaceData) * (node->numAtmInterfaces));

    aal5DataPtr->saalNodeInfo = NULL;

    for (i = 0; i < node->numAtmInterfaces; i++)
    {
        // Set ATM interface specific info
        Aal5InitInterface(node,nodeInput,i);
    }

    // Init the buffer List and
    // reassembly buffer list for that node
    ListInit(node, &aal5DataPtr->reAssBuffList);
    ListInit(node, &aal5DataPtr->bufferList);

    // Init Aal5 Forwarding Table
    Aal5InitFwdTable(node);

    // Init translation Table
    Aal5InitTransTable(node);

    // If the node is an END system
    // it is able to setup a connection
    // Thus initiate connection Table

    if (node->adaptationData.endSystem)
    {
        //Init connection table
        Aal5InitConncTable(node);
    }

    // Init AAL5 Statistics
    memset(&(aal5DataPtr->stats), 0, sizeof(Aal5Stats));

    // Routing Init
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ATM-STATIC-ROUTE",
        &retVal,
        buf);

    if ((retVal == TRUE) && (strcmp(buf, "YES") == 0))
    {
        AtmRoutingStaticInit(node, nodeInput);

        aal5DataPtr->rouitingLayerPtr =
            (char*)MEM_malloc(sizeof(char));
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "Static Routing not specified \n \n");
        ERROR_ReportWarning(err);
    }

    // set Atm Router ID

    memcpy(&(aal5DataPtr->atmRouterId),
        &aal5DataPtr->myIntfData[DEFAULT_INTERFACE].atmIntfAddr,
        sizeof(AtmAddress));

    // signalling init
    AtmSAALInit(node,
        (SaalNodeData**)&aal5DataPtr->saalNodeInfo,
        nodeInput);
}


// /**
// FUNCTION    :: Aal5PerformsReassemblyProcess
// LAYER       :: Adaptation Layer
// PURPOSE     :: Reassemble the segmented packets
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// + aalMsgInfo : Aal5MsgInfo* : Pointer to message information
// RETURN       : Aal5ReAssItem* : Pointer to aal5 reassemble item
// **/
Aal5ReAssItem* Aal5PerformsReassemblyProcess(
    Node* node,
    Message* msg,
    Aal5MsgInfo* aalMsgInfo)
{
    // START REASSEMBLY PROCESS
    BOOL found = FALSE;
    Aal5ReAssItem* reAssData = NULL ;
    ListItem* item = NULL;
    unsigned short incomingVCI = aalMsgInfo->incomingVCI;
    int inIntf = aalMsgInfo->incomingIntf;
    unsigned char inVPI = aalMsgInfo->incomingVPI ;

    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    item = aal5DataPtr->reAssBuffList->first;

    //First chk the reAssBuff List Item for matching VCI
    while (item)
    {
        reAssData = (Aal5ReAssItem*) item->data;

        if (DEBUG)
        {
            printf(" NODE %u: \n", node->nodeId);
            printf(" searching for VCI %d \n",incomingVCI);
            printf(" available VCI %d \n", reAssData->VCI);
        }

        if ((reAssData->VCI == incomingVCI)
            && (reAssData->inIntf == inIntf))
        {
            // first chk the validity of recvd data

            if (((reAssData->iduNumber + 1) * SAR_PDU_LENGTH) >
                MAX_SDU_DELIVER_LENGTH)
            {
                aal5DataPtr->stats.numAtmSduDropped++;

                return reAssData;
            }

            // It shall copy interface-Data/ SAR-SDU to the
            // reassembly buffer.
            memcpy(reAssData->reAssBuff,
                MESSAGE_ReturnPacket(msg),
                MESSAGE_ReturnPacketSize(msg));

            // increase idu Number reAssBuff should be
            // increased to store nextMsg
            reAssData->iduNumber++;
            reAssData->reAssBuff += SAR_PDU_LENGTH;

            found = TRUE;
            break;
        }
        item = item->next;
    }//End while

    // If Matching Item is not already found Create a new item
    if (!found)
    {
        // create a new Item in the list
        reAssData = (Aal5ReAssItem*)MEM_malloc(sizeof(Aal5ReAssItem));
        memset(reAssData, 0, sizeof(Aal5ReAssItem));

        reAssData->VCI =  incomingVCI;
        reAssData->iduNumber = 0;
        reAssData->reAssBuff = (char*)MEM_malloc(MAX_SDU_DELIVER_LENGTH);
        reAssData->cpcsPdu = reAssData->reAssBuff;
        reAssData->inIntf = inIntf;
        reAssData->VPI = inVPI;
        reAssData->msgInfo = MESSAGE_Duplicate(node, msg);

        // It shall copy interface-Data/ SAR-SDU to the
        // reassembly buffer.
        memcpy(reAssData->reAssBuff,
            MESSAGE_ReturnPacket(msg),
            MESSAGE_ReturnPacketSize(msg));

        // increase idu Number reAssBuff should be
        // increased to store nextMsg
        reAssData->iduNumber++;
        reAssData->reAssBuff += SAR_PDU_LENGTH;

        // Add to ReAssBuff List
        ListInsert(node, aal5DataPtr->reAssBuffList, 0,
            (void*) reAssData);

         if (DEBUG)
        {
            printf(" NODE %u: \n", node->nodeId);
            printf(" Entering VCI %d \n",incomingVCI);
        }
    }

    // Packet is reassembled here
    aal5DataPtr->stats.numPktReassembled++;

    return reAssData ;
}


// /**
// FUNCTION    :: Aal5RemoveItemFromReassBuffList
// LAYER       :: Adaptation Layer
// PURPOSE     :: Once the packet is formed after reassembly
//                it is cleared from the reassembly list
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + incomingVCI : unsigned short : Incomming VCI value
// + inIntf     : int : incoming Intf
// RETURN       : void : None
// **/
void Aal5RemoveItemFromReassBuffList(
    Node* node,
    unsigned short incomingVCI,
    int inIntf)
{
    Aal5ReAssItem* reAssData = NULL ;
    ListItem* item = NULL;
    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    item = aal5DataPtr->reAssBuffList->first;

    //First chk the reAssBuff List Item for matching VCI
    while (item)
    {
        reAssData = (Aal5ReAssItem*) item->data;

        if ((reAssData->VCI == incomingVCI)
            &&(reAssData->inIntf == inIntf))
        {
            // If matching entry found remove
            // that from reAssembly buffer list
            if (reAssData->msgInfo != NULL)
            {
                MESSAGE_Free(node, reAssData->msgInfo);
            }
            ListGet(node, aal5DataPtr->reAssBuffList, item, TRUE, FALSE);
            return;
        }
        item = item->next ;
    } // End of while
}


// /**
// FUNCTION    :: Aal5PassMsgToCpcsSublayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Pass the upper layer message to CPCS sublayer
//                for processing
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// + aalMsgInfo : Aal5MsgInfo* : Pointer to message information
// RETURN       : void : None
// **/
void Aal5PassMsgToCpcsSublayer(
    Node* node,
    Message* msg,
    Aal5MsgInfo* aalMsgInfo)
{
    Aal5CpcsPrimitive* primitiveInfo ;
    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    // Start processing SDU in CPCS layer
    aal5DataPtr->stats.numCpcsSduSent++;

    // create a new primitive to send info to CPCS sublayer
    MESSAGE_SetEvent(msg, MSG_ATM_ADAPTATION_CpcsUnidataInvoke);
    MESSAGE_SetLayer(msg, ADAPTATION_LAYER, ATM_PROTOCOL_AAL);
    MESSAGE_SetInstanceId(msg, 0);

   // Add AAL5 Message specific info in the info field of Msg
    MESSAGE_InfoAlloc(node, msg, sizeof(Aal5MsgInfo));
    memcpy(MESSAGE_ReturnInfo(msg), aalMsgInfo, sizeof(Aal5MsgInfo));

    // Add cpcs layer specific header or primitive
    // Primitives are sent in the header field of message
    MESSAGE_AddHeader(node, msg,
        sizeof(Aal5CpcsPrimitive), TRACE_AAL5);

    primitiveInfo = (Aal5CpcsPrimitive*)msg->packet;

    // More Field indicate end of cpss SDU
    primitiveInfo->more = 0;

    // set other primitive info
    primitiveInfo->cpcsCI = 0;
    primitiveInfo->cpcsLP = 0;
    primitiveInfo->cpcsUU = 0;
    primitiveInfo->receptionStatus = 0;

    MESSAGE_Send(node, msg, 0);
}


// /**
// FUNCTION    :: Aal5PassCpcsPduToSARSublayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Pass the upper layer message to SAR sublayer
//                for processing
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// + cpcsPrimitive : Aal5CpcsPrimitive* : pointer to CPCS primitive
// RETURN       : void : None
// **/
void Aal5PassCpcsPduToSARSublayer(
    Node* node,
    Message* msg,
    Aal5CpcsPrimitive* cpcsPrimitive)
{
    Aal5SarPrimitive sarPrimitive;

    // set the primitive field
    sarPrimitive.more = 0;
    sarPrimitive.sarCI = (unsigned short)cpcsPrimitive->cpcsCI;
    sarPrimitive.sarLP = (unsigned short)cpcsPrimitive->cpcsLP;

    // create a new msg to send info to the SAR Sublayer
    MESSAGE_SetEvent(msg, MSG_ATM_ADAPTATION_SarUnidataInvoke);
    MESSAGE_SetLayer(msg, ADAPTATION_LAYER, ATM_PROTOCOL_AAL);
    MESSAGE_SetInstanceId(msg, 0);

    // Add SAR layer specific header or primitive
    MESSAGE_AddHeader(node, msg,
        sizeof(Aal5SarPrimitive), TRACE_AAL5);

    // Primitives are passed in the header field of message
    memcpy((Aal5SarPrimitive*)msg->packet,
        &sarPrimitive, sizeof(Aal5SarPrimitive));

    // Send Message for Sar Layer
    MESSAGE_Send(node,
        MESSAGE_Duplicate(node, msg),
        0);
}


// /**
// FUNCTION    :: Aal5PassSarPduToAtmlayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Pass the upper layer message to
//                ATM layer2 for processing
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + sarPdu     : char* : Pointer to SAR PDU
// + primitive  : Aal5AtmDataPrimitive* : pointer to aal5
//                to ATM layer2 data
// + aalMsgInfo : Aal5MsgInfo* : Pointer to aal5 message information.
// + orgMsg     : Message* : Pointer to origianl packet
// RETURN       : void : None
// **/
void Aal5PassSarPduToAtmlayer(
    Node* node,
    char* sarPdu,
    Aal5AtmDataPrimitive* primitive,
    Aal5MsgInfo* aalMsgInfo,
    Message* orgMsg)
{
    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    //Create a new message to send info to ATM Layer2
    Message* newMsg = MESSAGE_Alloc(node,
                                    ATM_LAYER2,
                                    0,
                                    MSG_ATM_LAYER2_AtmDataRequest);

    // Alloc packet to store/pass the upper layer info
    MESSAGE_PacketAlloc(node,
        newMsg,
        SAR_PDU_LENGTH,
        TRACE_AAL5);

    // SAR-PDU of 48 octets are carried in msgPkt
    memcpy(MESSAGE_ReturnPacket(newMsg), sarPdu, SAR_PDU_LENGTH);

    // firstly, copy over info fields of origianl packet
    MESSAGE_CopyInfo(node, newMsg, orgMsg);

    MESSAGE_InfoAlloc(node, newMsg, sizeof(Aal5ToAtml2Info));
    Aal5ToAtml2Info* aal5ToAtml2Info =
            (Aal5ToAtml2Info*) MESSAGE_ReturnInfo(newMsg);

    aal5ToAtml2Info->atmCI = primitive->atmCI;
    aal5ToAtml2Info->atmLP = primitive->atmLP;
    aal5ToAtml2Info->atmUU = primitive->atmUU;
    aal5ToAtml2Info->incomingIntf = aalMsgInfo->incomingIntf;
    aal5ToAtml2Info->incomingVCI = aalMsgInfo->incomingVCI;
    aal5ToAtml2Info->incomingVPI = aalMsgInfo->incomingVPI;
    aal5ToAtml2Info->outIntf = aalMsgInfo->outIntf;
    aal5ToAtml2Info->outVCI = aalMsgInfo->outVCI;
    aal5ToAtml2Info->outVPI = aalMsgInfo->outVPI;

    if (DEBUG)
    {
        if (aalMsgInfo->incomingVCI != 5)
        {
            printf(" %u:SEND: AAL5 send msg to ATM layer2 of size %d \n",
                node->nodeId, MESSAGE_ReturnPacketSize(newMsg));

            printf(" data AUU has value %d \n", aal5ToAtml2Info->atmUU);

            printf(" VCI = %d inIntf %d outIntf = %d\n",
                aalMsgInfo->incomingVCI, aalMsgInfo->incomingIntf,
                aalMsgInfo->outIntf);
        }
    }

    // free SAR-PDU from which this newMsg is created
    MEM_free(sarPdu);

    // cell send to ATM Layer
    aal5DataPtr->stats.numAtmSduSent++;

    MESSAGE_Send(node, newMsg, 0);
}


// /**
// FUNCTION    :: Aal5BackSarPduToCpcsSublayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Pass the lower layer message to CPCS for processing.
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// + sarPrimitive : Aal5SarPrimitive* : SAR primitive pointer
// + aalMsgInfo : Aal5MsgInfo* : Pointer to aal5 message information.
// RETURN       : void : None
// **/
void Aal5BackSarPduToCpcsSublayer(
    Node* node,
    Message* msg,
    Aal5SarPrimitive* sarPrimitive,
    Aal5MsgInfo* aalMsgInfo)
{
    // create a new primitive to send info to CPCS sublayer
    MESSAGE_SetEvent(msg, MSG_ATM_ADAPTATION_SarUnidataSignal);
    MESSAGE_SetLayer(msg, ADAPTATION_LAYER, ATM_PROTOCOL_AAL);
    MESSAGE_SetInstanceId(msg, 0);

    // Add AAL5 Message specific info in the info field of Msg
    MESSAGE_InfoAlloc(node, msg, sizeof(Aal5MsgInfo));
    memcpy(MESSAGE_ReturnInfo(msg), aalMsgInfo, sizeof(Aal5MsgInfo));

    // Add Sar layer specific header or primitive
    MESSAGE_AddHeader(node, msg,
        sizeof(Aal5SarPrimitive), TRACE_AAL5);

    // Primitives are sent in the header field of message
    memcpy((Aal5SarPrimitive*)msg->packet,
        sarPrimitive, sizeof(Aal5SarPrimitive));

    MESSAGE_Send(node, MESSAGE_Duplicate(node, msg), 0);
}


// /**
// FUNCTION    :: Aal5BackInfoFromCpcsSublayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Pass the message to upper layer from CPCS
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + cpcsPdu    : char* : Pointer to cpcs PDU
// + payloadLength : unsigned int : Length of payload.
// + sarPrimitive : Aal5SarPrimitive* : pointer to SAR primitive
// + aalMsgInfo : Aal5MsgInfo* : Pointer to aal5 message information.
// + msgInfo    : Message* : First fragment for copy over info
// RETURN       : void : None
// **/
void Aal5BackInfoFromCpcsSublayer(
    Node* node,
    char* cpcsPdu,
    unsigned int payloadLength,
    Aal5SarPrimitive* sarPrimitive,
    Aal5MsgInfo* aalMsgInfo,
    Message* msgInfo)
{
    Message* newMsg;
    Aal5CpcsPrimitive primitive;

    // create a new message to send info from CPCS sublayer
    newMsg = MESSAGE_Alloc(node,
        ADAPTATION_LAYER,
        ATM_PROTOCOL_AAL,
        MSG_ATM_ADAPTATION_CpcsUnidataSignal);

    // Alloc packet to store/pass the upper layer info
    MESSAGE_PacketAlloc(node,
        newMsg,
        payloadLength,
        TRACE_AAL5);

    //Message represent a complete CPCS-PDU
    memcpy((char*)MESSAGE_ReturnPacket(newMsg),
        cpcsPdu, payloadLength);

    // Set CPCSPrimitive Info
    primitive.cpcsCI = sarPrimitive->sarCI;
    primitive.cpcsLP = sarPrimitive->sarLP;

    // Copy all info fields of the first fragment
    MESSAGE_CopyInfo(node, newMsg, msgInfo);

    // Add AAL5 Message specific info in the info field of Msg
    MESSAGE_InfoAlloc(node, newMsg, sizeof(Aal5MsgInfo));
    memcpy(MESSAGE_ReturnInfo(newMsg), aalMsgInfo, sizeof(Aal5MsgInfo));

    // Add CPCS layer specific header or primitive
    MESSAGE_AddHeader(node, newMsg,
        sizeof(Aal5CpcsPrimitive), TRACE_AAL5);

    // Primitives are sent in the header field of message
    memcpy((Aal5CpcsPrimitive*)newMsg->packet,
        &primitive, sizeof(Aal5CpcsPrimitive));

    MESSAGE_Send(node, newMsg, 0);
}


// /**
// FUNCTION    :: Aal5DeliverDataPacket
// LAYER       :: Adaptation Layer
// PURPOSE     :: AAL5 handed over the packet to Adaptation layer
//                to send it to the upper layer
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// + incomingIntf : int : Incomming interface.
// RETURN       : void : None
// **/
void Aal5DeliverDataPacket(
    Node* node,
    Message* msg,
    int incomingIntf)
{
    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    // After receiving a data packet information
    // the end system need to handed it over to the upper layer
    // so it is processed accprdingly in adaptation layer

    // QUALNET SPECIFIC ADDITION
    // To manage QUALNET specific trace two false header is added

    MESSAGE_AddHeader(node, msg, 0, TRACE_UDP); // for transport layer
    MESSAGE_AddHeader(node, msg, 0, TRACE_IP); // for network layer
    MESSAGE_AddHeader(node, msg, 0, TRACE_IP); // for LLC encapsulation

    aal5DataPtr->stats.numPktFwdToIPNetwork++ ;
    ADAPTATION_DeliverPacketToNetworkLayer(node, msg, incomingIntf);
}


// /**
// FUNCTION    :: Aal5ReceivePacketFromCpcsSublayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: After reassembly & other checking CPCS sublayer
//                finaly deliver packet to AAl5 layer
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// + incomingIntf : int : Incomming interface.
// + inVCI      : unsigned short : incoming VCI for this application
// RETURN       : void : None
// **/
void Aal5ReceivePacketFromCpcsSublayer(
    Node* node,
    Message* msg,
    int incomingIntf,
    unsigned short inVCI)
{
    Aal5MsgInfo aalMsgInfo;
    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    // Extract Msg Info
    memcpy(&aalMsgInfo, MESSAGE_ReturnInfo(msg), sizeof(Aal5MsgInfo));

    // Check if this is data packet or signalling packet
    // If it is data packet handover it to IP
    // If signalling Packet handover it to SAAL

    if (inVCI == ATM_SAAL_VCI)
    {
        // Recvd Signaling Pkt in AAL5
        aal5DataPtr->stats.numSaalPktRecvd++ ;

        // At present packet is directly processed
        SaalHandleProtocolPacket(node,
            MESSAGE_Duplicate(node, msg), incomingIntf);
    }
    else
    {
        if (DEBUG)
        {
            printf(" ________________________________________\n");
            printf(" Node %u: Recv_ing Data \n", node->nodeId);
            printf(" ________________________________________\n");
        }

        // Recvd Data Pkt in AAL5 and start processing
        aal5DataPtr->stats.numDataPktRecvd++;

        Aal5DeliverDataPacket(node, MESSAGE_Duplicate(node, msg),
            incomingIntf);
    }
}


// /**
// FUNCTION    :: Aal5ProcessDataPacket
// LAYER       :: Adaptation Layer
// PURPOSE     :: ATM start processing the Data Packet
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// + VCI        : unsigned short : Virtual Connection Identifier
// + VPI        : unsigned char : Virtual Path Identifier
// + row        : AtmTransTableRow* : Pointer to transfer-table row.
// RETURN       : void : None
// **/
void Aal5ProcessDataPacket(
    Node* node,
    Message* msg,
    unsigned short VCI,
    unsigned char VPI,
    AtmTransTableRow* row)
{

    Aal5MsgInfo aalMsgInfo;
    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    if (DEBUG)
    {
        printf(" ________________________________________\n");
        printf(" Node %u: transfering Data \n", node->nodeId);
        printf(" ________________________________________\n");
    }

    // Start processing data packet
    aal5DataPtr->stats.numDataPktSend++;

    // This Msg is now ready to emerge from AAL5 layer
    // and moving to CPCS & SAR sublayer for
    // achieving 48 byte structure, segmentation
    // and other functionalities

    // set the Info Field
    aalMsgInfo.incomingVCI = VCI;
    aalMsgInfo.incomingVPI = VPI;

    // in Intf is not used further so kept as invalid
    aalMsgInfo.incomingIntf = -1;

    aalMsgInfo.outIntf = row->outIntf;
    aalMsgInfo.outVCI = row->finalVCI;
    aalMsgInfo.outVPI = row->finalVPI;

    if (DEBUG)
    {
        printf(" Node %u send data Pkt :\n", node->nodeId);
        printf(" Packet size %d \n",
            MESSAGE_ReturnPacketSize(msg));
        printf("Actual Packet size %d \n",
            MESSAGE_ReturnActualPacketSize(msg));

        Aal5PrintTransTable(node);
    }

    // AAl5 pass msg to CPCS sublayer in
    // CPCS-UNIDATA invokePrimitive
    Aal5PassMsgToCpcsSublayer(node, msg, &aalMsgInfo);
}


// /**
// FUNCTION    :: Aal5EnterDataInBuffer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Keep the data packet in the buffer
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : Virtual Connection Identifier
// + VPI        : unsigned char : Virtual Path Identifier
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void Aal5EnterDataInBuffer(Node* node,
                           unsigned short VCI,
                           unsigned char VPI,
                           Message* msg)
{
    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    // Need to store the data packet in buffer
    Aal5BufferListItem* newBuffItem;

    // Store Item in Buffer
    newBuffItem = (Aal5BufferListItem*)
        MEM_malloc(sizeof(Aal5BufferListItem));

    newBuffItem->timeStamp = node->getNodeTime();
    newBuffItem->VCI = VCI;
    newBuffItem->VPI = VPI;

    // Note down the msg pointer address
    newBuffItem->dataInfo = msg ;

    // Insert this item in Buffer
    ListInsert(node, aal5DataPtr->bufferList,
        0, (void*)newBuffItem);

    if (DEBUG)
    {
        char buf[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(newBuffItem->timeStamp, buf);

        printf("%u enter data in buff for VCI %d & time %s   ",
            node->nodeId, newBuffItem->VCI, buf);

        TIME_PrintClockInSecond(node->getNodeTime(), buf);
        printf("---Current time(s) = %s\n",buf);
    }
}


// /**
// FUNCTION    :: Aal5ClearDataInBuffer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Remove the data packet from the Buffer
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : Virtual Connection Identifier
// + VPI        : unsigned char : Virtual Path Identifier
// RETURN       : void : None
// **/
void Aal5ClearDataInBuffer(Node* node,
                           unsigned short VCI,
                           unsigned char VPI)
{
    ListItem* item;
    ListItem* tempItem;
    Message* buffMsg;

    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    // Extract the data packet from buffer
    Aal5BufferListItem* thisBuffItem;

    // check for matching entry from the buffer list
    item = aal5DataPtr->bufferList->first;

    //First chk the Buffer List Item for matching VCI
    while (item)
    {
        thisBuffItem = (Aal5BufferListItem*) item->data;

        if ((thisBuffItem->VCI == VCI)
            && (thisBuffItem->VPI == VPI))
        {
             // Note down the msg pointer address
            buffMsg = thisBuffItem->dataInfo ;

            // store the item pointer
            tempItem = item->next;

            if (DEBUG)
            {
                char buf[MAX_STRING_LENGTH];
                TIME_PrintClockInSecond(thisBuffItem->timeStamp, buf);

                printf("%u clear data for VCI %d & time %s \n",
                    node->nodeId, thisBuffItem->VCI, buf);
            }

            // remove the item from buffer
            ListGet(node, aal5DataPtr->bufferList,
                 item, TRUE, FALSE);

            MESSAGE_Free(node, buffMsg);

            item = tempItem;
        }
        else
        {
            item = item->next;
        }
    }
}


// /**
// FUNCTION    :: AalReceivePacketFromNetworkLayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: A packet is received from the network layer
//                for processing in the ATM layer
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void AalReceivePacketFromNetworkLayer(Node *node,
                                      Message *msg)
{
    Address appSrcAddr;
    Address appDstAddr;
    unsigned short appSrcPort = 0;
    unsigned short appDstPort = 0;
    Aal5ConncTableRow* conncRow = NULL;
    AtmTransTableRow* row = NULL;
    appSrcAddr.networkType = NETWORK_INVALID;
    appDstAddr.networkType = NETWORK_INVALID;

    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);
    IpHeaderType* ipHeader = (IpHeaderType *)(msg->packet +
        sizeof(AdaptationLLCEncapInfo));

    // Packet Captured
    if (DEBUG)
    {
        printf("\n\n#%u receive packet from Network \n",
            node->nodeId);
        printf(" has IP_P %d ip_src %x ip_dst %x\n",
            ipHeader->ip_p, ipHeader->ip_src, ipHeader->ip_dst);
    }

    aal5DataPtr->stats.numPktFromIPNetwork++;

    // Check for validity of Data

    if ((ipHeader->ip_dst == ANY_DEST)
        || NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
    {
        ERROR_ReportWarning("Can't process broadcast or multicast");
        aal5DataPtr->stats.numIpPktDiscarded ++;
        return;
    }

    if (!node->adaptationData.endSystem)
    {
        ERROR_ReportWarning("Not an ATM EndSystem: unable to process");
        aal5DataPtr->stats.numIpPktDiscarded ++;
        return;
    }

    if (ipHeader->ip_p == IPPROTO_UDP)
    {
        TransportUdpHeader* udpHeader
            = (TransportUdpHeader*)(ipHeader + 1);

        // Check the source and destination address & port

        appSrcAddr.networkType = NETWORK_IPV4;
        appSrcAddr.interfaceAddr.ipv4 = ipHeader->ip_src;

        appDstAddr.networkType = NETWORK_IPV4;
        appDstAddr.interfaceAddr.ipv4 = ipHeader->ip_dst;

        appSrcPort = udpHeader->sourcePort;
        appDstPort = udpHeader->destPort;

    }
    else if (ipHeader->ip_p == IPPROTO_TCP)
    {
        struct tcphdr* tcpHeader = (struct tcphdr*)(ipHeader + 1);

        // Check the source and destination address & port

        appSrcAddr.networkType = NETWORK_IPV4;
        appSrcAddr.interfaceAddr.ipv4 = ipHeader->ip_src;

        appDstAddr.networkType = NETWORK_IPV4;
        appDstAddr.interfaceAddr.ipv4 = ipHeader->ip_dst;

        appSrcPort = tcpHeader->th_sport;
        appDstPort = tcpHeader->th_dport;
    }
    else
    {
        ERROR_ReportError("Unknown type packet in Adaptation");
    }

    // This is an application packet so process it using AAL
    // Set Initial VPI & VCI

    conncRow = Aal5SearchForMatchingEntryInConncTable(node, appSrcAddr,
        appDstAddr, appSrcPort, appDstPort);

    // Check the signaling status for this entry
    // process incoming msg accordingly

    switch(conncRow->saalStatus)
    {
    case SAAL_NOT_YET_STARTED:
        {
            // enter data packet in buffer
            Aal5EnterDataInBuffer(node, conncRow->VCI,
                conncRow->VPI, msg);

            // PATH is not yet established for this application
            // So start ATM signalling process

            SaalStartSignalingProcess(node, conncRow->VCI,
                conncRow->VPI,
                appSrcAddr,
                appDstAddr);

            break;
        }

    case SAAL_IN_PROGRESS:
        {
            // enter data in buffer
            Aal5EnterDataInBuffer(node, conncRow->VCI,
                conncRow->VPI, msg);

            break;
        }

    case SAAL_COMPLETED:
        {
            // signaling complete so path must
            // be established for this entry
            // search for matching row in trans table

            row = Aal5SearchTransTable(node, conncRow->VCI, conncRow->VPI);

            if (!row)
            {
                char errStr[MAX_STRING_LENGTH];

                // Shouldn't get here.
                sprintf(errStr, "Node %u: No entry in Trans Table\n",
                    node->nodeId);

                ERROR_Assert(FALSE, errStr);
            }

            if (DEBUG)
            {
                char buf[MAX_STRING_LENGTH];
                TIME_PrintClockInSecond(node->getNodeTime(), buf);

                printf("%u PATH ESTABLISHED -- ", node->nodeId);
                printf("---Current time(s) = %s\n",buf);
            }
            // Process the data Packet in AAL5 layer
            Aal5ProcessDataPacket(node, msg, conncRow->VCI,
                conncRow->VPI, row);

            break;
        }

    case SAAL_TERMINATED:
        {
            // Test...
            //printf("\nSAAL Terminated\n");

            // This connection is rejected so
            // clear the related entry from buffer

            Aal5ClearDataInBuffer(node, conncRow->VCI, conncRow->VPI) ;
            break;
        }

    default:
        //  case SAAL_INVALID_STATUS:
        // no need to process it

        char errStr[MAX_STRING_LENGTH];

        // Shouldn't get here.
        sprintf(errStr, "Node %u: No Valid Saal State for VCI %d\n",
            node->nodeId, conncRow->VCI);

        ERROR_Assert(FALSE, errStr);

        break;

    }
}


// /**
// FUNCTION    :: AalSendSignalingMsgToLinkLayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: After creating a signaling message it needs to be passed
//                thru various sublayer for processing
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + srcIdentifier: AtmAddress* : Pointer to ATM source.
// + destIdentifier : AtmAddress* : Pointer to ATM destination.
// + ttl        : unsigned : Time to leave.
// + outgoingInterface : int : outgoing interface index.
// + nextHop    : AtmAddress* : Pointer to nextHop.
// + msgType    : unsigned short : Message type.
// RETURN       : void : None
// **/
void AalSendSignalingMsgToLinkLayer(
    Node *node,
    Message *msg,
    AtmAddress* srcIdentifier,
    AtmAddress* destIdentifier,
    unsigned ttl,
    int outgoingInterface,
    AtmAddress* nextHop,
    unsigned short msgType)
{
    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    // Start processing SDU in CPCS layer
    unsigned short VCI = ATM_SAAL_VCI;
    Aal5MsgInfo aalMsgInfo;

    if (DEBUG)
    {
        SaalMsgHeader* saalMsgHdr =
            (SaalMsgHeader*) MESSAGE_ReturnPacket(msg);

        printf(" %u is trying to send Saal Pkt from %x \n",
            node->nodeId, srcIdentifier->deviceAddr_pt1);
        printf(" for dst %x & nextHop %x VCI %d\n",
            destIdentifier->deviceAddr_pt1,
            nextHop->deviceAddr_pt1, VCI);
        printf(" this is %d SAAL pkt size %d \n",
            saalMsgHdr->messageType,
            MESSAGE_ReturnPacketSize(msg));
    }

    // Check for Valid Destination

    if ((outgoingInterface == SAAL_INVALID_INTERFACE)
        ||(nextHop->AFI == 0))
    {
        MESSAGE_Free(node, msg);
        return;
    }

    if ((srcIdentifier->ESI_pt1 == destIdentifier->ESI_pt1)
        &&(srcIdentifier->ESI_pt2 == destIdentifier->ESI_pt2))
    {
        MESSAGE_Free(node, msg);
        return;
    }

    // This Msg is now ready to emerge from AAL5 layer
    // and moving to CPCS & SAR sublayer for
    // achieving 48 byte structure, segmentation
    // and other functionalities

    // Start processing Signaling Pkt in AAL
    aal5DataPtr->stats.numSaalPktSend++;

    // SENDING SIDE: Signaling Msg is processed

    // set the AAL5 specific Info field in sending Side
    memset(&aalMsgInfo, 0, sizeof(Aal5MsgInfo));

    aalMsgInfo.incomingIntf = DEFAULT_INTERFACE;
    aalMsgInfo.incomingVCI = VCI;
    aalMsgInfo.incomingVPI = 0;
    aalMsgInfo.outIntf = outgoingInterface;
    aalMsgInfo.outVCI = VCI;
    aalMsgInfo.outVPI = 0;

    // AAl5 pass msg to CPCS sublayer in CPCS-UNIDATA invokePrimitive
    Aal5PassMsgToCpcsSublayer(node, msg, &aalMsgInfo);
}


// /**
// FUNCTION    :: Aal5ProcessCpcsUnidataInvoke
// LAYER       :: Adaptation Layer
// PURPOSE     :: Add CPCS specific tailer and send the msg to SAR Sub-Layer
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void Aal5ProcessCpcsUnidataInvoke(Node* node, Message* msg)
{
    Aal5CpcsPrimitive cpcsPrimitive;
    Aal5CpcsPduTrailer trailer;

    int padField = 0;

    // Upon Reception of CPCS-UNIDATA invoke primitive
    // primitives are extracted from headerField
    memcpy(&cpcsPrimitive, msg->packet,
        sizeof(Aal5CpcsPrimitive));

    MESSAGE_RemoveHeader(node, msg,
        sizeof(Aal5CpcsPrimitive), TRACE_AAL5);

    // Set the msg by adding CPCS trailer & pad
     // Set Trailer field for CPCSPdu Trailer
    trailer.cpcsUU = cpcsPrimitive.cpcsUU;
    trailer.cpi = 0;
    trailer.payloadLength = (unsigned short)MESSAGE_ReturnPacketSize(msg);
    trailer.crc  =0;

    // Add different header

    // Add some filler octets to complements the CPCS-PDU
    // including CPCS-PDU payload, padding field and the
    // CPCS-PDU trailer, to an integral multiple of 48 octets
    if ((MESSAGE_ReturnPacketSize(msg) + sizeof(Aal5CpcsPduTrailer))%48)
    {
        //add pad field
        padField = 48 -
            ((MESSAGE_ReturnPacketSize(msg) +
                sizeof(Aal5CpcsPduTrailer))%48);
    }
     // Add pad field as header
    MESSAGE_AddHeader(node, msg, padField, TRACE_AAL5);
    memset(msg->packet, 0, padField);

    // Add cpcs trailer as header
    MESSAGE_AddHeader(node, msg,
        sizeof(Aal5CpcsPduTrailer), TRACE_AAL5);

    memcpy((Aal5CpcsPduTrailer*)msg->packet,
        &trailer, sizeof(Aal5CpcsPduTrailer));

    // After constructing the CpcsPdu, it is passed to
    // SAR sublayer in a SAR-UNIDATA invokePrimitive
     Aal5PassCpcsPduToSARSublayer(node, msg, &cpcsPrimitive);
}


// /**
// FUNCTION    :: Aal5ProcessSarUnidataInvoke
// LAYER       :: Adaptation Layer
// PURPOSE     :: Process the packet in SAR sub layer.
//                Performs segmentation.
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void Aal5ProcessSarUnidataInvoke(Node* node, Message* msg)
{
    Aal5SarPrimitive sarPrimitive;
    int cpcsPduLn;
    char* cpcsPdu;
    int numberOfSarSdu;
    int i;
    int actualPacketSize ;

    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    // Upon Reception of SAR-UNIDATA invoke primitive
    // primitives are extracted from header Field
    memcpy(&sarPrimitive, msg->packet,
        sizeof(Aal5SarPrimitive));

    MESSAGE_RemoveHeader(node, msg,
        sizeof(Aal5SarPrimitive), TRACE_AAL5);

    // Extract Msg Info
    Aal5MsgInfo aalMsgInfo;
    memcpy(&aalMsgInfo, MESSAGE_ReturnInfo(msg), sizeof(Aal5MsgInfo));

    cpcsPduLn = MESSAGE_ReturnPacketSize(msg);
    cpcsPdu = MESSAGE_ReturnPacket(msg);

    actualPacketSize = MESSAGE_ReturnActualPacketSize(msg);

    // Test for packet before segmentation...
   if (DEBUG)
    {
        printf(" \n\ncpcsPdu Size is %d \n", cpcsPduLn);
        printf(" payload %" TYPES_SIZEOFMFT "u  + trailer %" TYPES_SIZEOFMFT "u \n",
            cpcsPduLn - sizeof(Aal5CpcsPduTrailer),
            sizeof(Aal5CpcsPduTrailer));
    }

    numberOfSarSdu = cpcsPduLn/48 ;

    // SAR sender start the segmenting process
    // if interface data has alength of more than 48 octets,
    // the SAR sender will generate more than one SAR-PDU

    for (i = 1; i <= numberOfSarSdu; i++)
    {
        Aal5AtmDataPrimitive dataRqstPr;
        int alreadyCopied = ((i-1) * SAR_PDU_LENGTH);

        dataRqstPr.atmUU = 0;
        dataRqstPr.atmLP = sarPrimitive.sarLP;
        dataRqstPr.atmCI= sarPrimitive.sarCI;

        // Construct sarPdu of 48 octet length
        char* sarPdu = (char*)MEM_malloc(SAR_PDU_LENGTH);
        memset(sarPdu, 0, SAR_PDU_LENGTH);

        // copied the actual packet part & rest i.e,
        // virtual payload filled with 0

        if (actualPacketSize > (alreadyCopied + SAR_PDU_LENGTH))
        {
            // this is copied from actual packet size
            memcpy(sarPdu, cpcsPdu, SAR_PDU_LENGTH);
        }
        else if (actualPacketSize > alreadyCopied)
        {
            // this is copied from actual packet size
            memcpy(sarPdu, cpcsPdu,
                (actualPacketSize - alreadyCopied));
        }

        cpcsPdu += SAR_PDU_LENGTH;

        // Packet is segmented here
        aal5DataPtr->stats.numPktSegmented++;

        // AUU parameters is set as 1 for last SAR-PDU
        if (i == numberOfSarSdu)
        {
            dataRqstPr.atmUU = 1;

        }

        // Pass SAR_PDU to ATM layer 2 using ATM-DATA Request
        Aal5PassSarPduToAtmlayer(node,
                                 sarPdu,
                                 &dataRqstPr,
                                 &aalMsgInfo,
                                 msg);
    }
}


// /**
// FUNCTION    :: Aal5ProcessATMDataIndication
// LAYER       :: Adaptation Layer
// PURPOSE     :: Aal5 receives message from ATM Layer2
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void Aal5ProcessATMDataIndication(Node* node, Message* msg)
{
    Aal5ToAtml2Info layerMsgInfo;
    Aal5SarPrimitive sarPrimitive;
    Aal5MsgInfo aalMsgInfo;

    // Upon Reception of ATM-DATA-INDICATION
    // info are extracted from header Field
    memcpy(&layerMsgInfo, MESSAGE_ReturnInfo(msg),
        sizeof(Aal5ToAtml2Info));

    if (DEBUG)
    {
        if (layerMsgInfo.incomingVCI != 5)
        {
            printf("RECV: For Node %u: \n", node->nodeId);
            printf(" packet Size is %d \n",
                MESSAGE_ReturnPacketSize(msg));

            printf(" atmUU = %d \n", layerMsgInfo.atmUU);
            printf(" incomingIntf = %d \n", layerMsgInfo.incomingIntf);
            printf(" incomingVCI= %d \n", layerMsgInfo.incomingVCI);
            printf(" incomingVPI= %d \n", layerMsgInfo.incomingVPI);
            printf(" outIntf= %d \n", layerMsgInfo.outIntf);
            printf(" outVCI= %d \n", layerMsgInfo.outVCI);
            printf(" outVPI= %d \n", layerMsgInfo.outVPI);
        }
    }

    // if this an ATM switch it will not recv any data Indication
    // bcoz data will be forwarded to end-systems thru ATM layer2

    // set AAl Msg Info
    aalMsgInfo.incomingIntf = layerMsgInfo.incomingIntf;
    aalMsgInfo.incomingVCI =  layerMsgInfo.incomingVCI;
    aalMsgInfo.incomingVPI = layerMsgInfo.incomingVPI;
    aalMsgInfo.outIntf = layerMsgInfo.outIntf;
    aalMsgInfo.outVCI = layerMsgInfo.outVCI;
    aalMsgInfo.outVPI = layerMsgInfo.outVPI;

    // set SAR Primitive
    sarPrimitive.more = !layerMsgInfo.atmUU;
    sarPrimitive.sarCI = layerMsgInfo.atmCI;
    sarPrimitive.sarLP = layerMsgInfo.atmLP;

    // send this info to CPCS sublayer
    Aal5BackSarPduToCpcsSublayer(node, msg,
        &sarPrimitive, &aalMsgInfo);
}


// /**
// FUNCTION    :: Aal5ProcessSarUnidataSignal
// LAYER       :: Adaptation Layer
// PURPOSE     :: Extract CPCS trailer after receiving this signal
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void Aal5ProcessSarUnidataSignal(Node* node, Message* msg)
{
    Aal5SarPrimitive sarPrimitive;
    Aal5CpcsPduTrailer* trailer;
    int  totalCpcsPduLn;
    int padLn;

    // Upon Reception of SAR-UNIDATA-SIGNAL
    // primitives are extracted from header Field
    memcpy(&sarPrimitive, msg->packet,
        sizeof(Aal5SarPrimitive));

    // Remove Sar Header
    MESSAGE_RemoveHeader(node, msg,
        sizeof(Aal5SarPrimitive), TRACE_AAL5);

    // Extract Msg Info
    Aal5MsgInfo aalMsgInfo;
    memcpy(&aalMsgInfo, MESSAGE_ReturnInfo(msg), sizeof(Aal5MsgInfo));

    if (MESSAGE_ReturnPacketSize(msg) > MAX_SDU_DELIVER_LENGTH)
    {
        if (DEBUG)
        {
            printf(" packet should be discarded \n");
        }
        return;
    }

    // Start reassembly process
    Aal5ReAssItem* reAssData =
        Aal5PerformsReassemblyProcess(node, msg, &aalMsgInfo);

    if (sarPrimitive.more)
    {
        return;
    }

    // Final Message is reconstructed

    // If more parameter of SAR-UNIDATA signal is 0,
    // the first eight octet represent the CPCS-PDU trailer

    trailer = (Aal5CpcsPduTrailer*)(reAssData->cpcsPdu);

    // Calculate length of received CPCS-PDU
    // and the pad Field length
    totalCpcsPduLn =  (reAssData->iduNumber * SAR_PDU_LENGTH);

    //   PadLn is derived from the totalLength
    padLn = totalCpcsPduLn - (trailer->payloadLength) -
        (sizeof(Aal5CpcsPduTrailer));

    // Check for validity of received Data
    if ((totalCpcsPduLn > MAX_SDU_DELIVER_LENGTH)
        ||(padLn > MAX_SDU_DELIVER_LENGTH))
    {
        if (DEBUG)
        {
            printf(" packet should be discarded \n");
        }

        // This packet is reassembled so it is removed from the bufefr
        MEM_free(reAssData->cpcsPdu);
        reAssData->cpcsPdu = NULL;

        Aal5RemoveItemFromReassBuffList(node,
            aalMsgInfo.incomingVCI, aalMsgInfo.incomingIntf);

        return;
    }

    // send this info to CPCS sublayer
    // after ignoring trailer & padfield data
    Aal5BackInfoFromCpcsSublayer(
        node,
        ((reAssData->cpcsPdu) + sizeof(Aal5CpcsPduTrailer) + padLn),
        trailer->payloadLength,
        &sarPrimitive,
        &aalMsgInfo,
        reAssData->msgInfo);

    // This packet is reassembled so it is removed from the bufefr
    MEM_free(reAssData->cpcsPdu);
    reAssData->cpcsPdu = NULL;

    Aal5RemoveItemFromReassBuffList(node,
        aalMsgInfo.incomingVCI, aalMsgInfo.incomingIntf);
}


// /**
// FUNCTION    :: Aal5ProcessCpcsUnidataSignal
// LAYER       :: Adaptation Layer
// PURPOSE     :: Process the received packet in CPCS sublayer
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void Aal5ProcessCpcsUnidataSignal(Node* node, Message* msg)
{
    Aal5CpcsPrimitive primitive;
    Aal5MsgInfo aalMsgInfo;

    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    // Upon Reception of CPCS-UNIDATA-SIGNAL
    // primitives are extracted from header Field
    memcpy(&primitive, msg->packet,
        sizeof(Aal5CpcsPrimitive));

    // Remove Sar Header
    MESSAGE_RemoveHeader(node, msg,
        sizeof(Aal5CpcsPrimitive), TRACE_AAL5);

    // Extract Msg Info
    memcpy(&aalMsgInfo, MESSAGE_ReturnInfo(msg), sizeof(Aal5MsgInfo));

    if (DEBUG)
    {
        printf("#%u : Final Msg (size %d) is ready \n",
            node->nodeId, MESSAGE_ReturnPacketSize(msg));
        printf(" inIntf = %d\n", aalMsgInfo.incomingIntf);
        printf(" VCI = %d\n", aalMsgInfo.incomingVCI);
    }

    // AalSdu received
    aal5DataPtr->stats.numCpcsSduRecv++;

    Aal5ReceivePacketFromCpcsSublayer(node, msg,
        aalMsgInfo.incomingIntf, aalMsgInfo.incomingVCI);
}


// /**
// FUNCTION    :: Aal5CollectDataFromBuffer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Collect the datat packet from buffer after
//                path establishment
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : VCI value
// + VPI        : unsigned char : VPI value
// RETURN       : void : None
// **/
void Aal5CollectDataFromBuffer(
    Node* node,
    unsigned short VCI,
    unsigned char VPI)
{
    ListItem* item;
    ListItem* tempItem;

    Message* buffMsg;

    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    // Extract the data packet from buffer
    Aal5BufferListItem* thisBuffItem;

    // check for matching entry from the buffer list
    item = aal5DataPtr->bufferList->first;

    //First chk the Buffer List Item for matching VCI
    while (item)
    {
        thisBuffItem = (Aal5BufferListItem*) item->data;

        if ((thisBuffItem->VCI == VCI)
            && (thisBuffItem->VPI == VPI))
        {
            // Matching entry found
            // extract the related info from Trans Table
            AtmTransTableRow* row =
                Aal5SearchTransTable(node, VCI, VPI);

            if (row == NULL)
            {
                char errStr[MAX_STRING_LENGTH];
                // Shouldn't get here.
                sprintf(errStr, "Node %u: No entry in Trans Table\n",
                    node->nodeId);

                ERROR_Assert(FALSE, errStr);
            }

            // Note down the msg pointer address
            buffMsg = thisBuffItem->dataInfo ;

            tempItem = item->next;

            // remove the item from buffer
            ListGet(node, aal5DataPtr->bufferList,
                item, TRUE, FALSE);

            // AAL5 process Data Packet
            Aal5ProcessDataPacket(node, buffMsg,
                VCI, VPI, row);

            item = tempItem;
        }
        else
        {
            item = item->next;
        }
    }
}


// /**
// FUNCTION    :: Aal5HandleProtocolPrimitive
// LAYER       :: Adaptation Layer
// PURPOSE     :: Handle the received protocol specific primitive
//                in various sublayer
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void
Aal5HandleProtocolPrimitive(Node* node, Message* msg)
{
    switch (msg->eventType)
    {
    case MSG_ATM_ADAPTATION_CpcsUnidataInvoke:
        {
            if (DEBUG)
            {
                printf("#%u CPCS received UnidataInvoke size %d\n",
                    node->nodeId, MESSAGE_ReturnPacketSize(msg));
            }

            // CPCS functionalities include:
            // Preserve CPCS-SDU
            // Preserve CPCS User to User Info
            // Padding
            // Handling of Conegestion Info
            // Handling of Loss Priority Info

            Aal5ProcessCpcsUnidataInvoke(node, msg);

            break;
        };

    case MSG_ATM_ADAPTATION_SarUnidataInvoke:
        {
            if (DEBUG)
            {
                printf("#%u SAR received UnidataInvoke size %d\n",
                    node->nodeId, MESSAGE_ReturnPacketSize(msg));
            }

            // SAR functionalities include:
            // Preserve SAR-SDU
            // Handling of Conegestion Info
            // Handling of Loss Priority Info

            Aal5ProcessSarUnidataInvoke(node, msg);

            break;
        };

    case MSG_ATM_ADAPTATION_ATMDataIndication:
        {
            if (DEBUG)
            {
                printf("#%u SAR received DataIndication size %d\n",
                    node->nodeId, MESSAGE_ReturnPacketSize(msg));
                printf("   received from LAYER2(virtual) \n");
            }

            Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);
            aal5DataPtr->stats.numAtmSduRecv++;

            Aal5ProcessATMDataIndication(node, msg);

            break;
        }
    case MSG_ATM_ADAPTATION_SarUnidataSignal:
        {
            if (DEBUG)
            {
                printf("#%u CPCS received SarUnidataSignal size %d\n",
                    node->nodeId, MESSAGE_ReturnPacketSize(msg));
            }

            Aal5ProcessSarUnidataSignal(node, msg);

            break;
        };
    case MSG_ATM_ADAPTATION_CpcsUnidataSignal:
        {
            if (DEBUG)
            {
                printf("#%u AAL received CpcsUnidataSignal size %d\n",
                    node->nodeId, MESSAGE_ReturnPacketSize(msg));
            }

            Aal5ProcessCpcsUnidataSignal(node, msg);

            break;
        };

    default:
        {
            char errStr[MAX_STRING_LENGTH];

            // Shouldn't get here.
            sprintf(errStr, "Node %u: Got invalid AAL5 primitive %d\n",
                node->nodeId, msg->eventType);
            printf(" Msg Size is %d \n", MESSAGE_ReturnPacketSize(msg));
            ERROR_Assert(FALSE, errStr);

        }
    }// end switch

   MESSAGE_Free(node, msg);
}


// /**
// FUNCTION    :: AtmAdaptationLayer5ProcessEvent
// LAYER       :: Adaptation Layer
// PURPOSE     :: Process the packet depending upon the type of ATM packet
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void
AtmAdaptationLayer5ProcessEvent(Node* node, Message* msg)
{
    switch(msg->protocolType)
    {
    case ATM_PROTOCOL_SAAL:
        {
            SaalHandleProtocolEvent(node, msg);
            break;
        }
    case ATM_PROTOCOL_AAL:
        {
            Aal5HandleProtocolPrimitive(node, msg);
            break;
        }
    default:

        printf("%u\n", MESSAGE_GetProtocol(msg));
        ERROR_ReportError("Undefined switch value");
        break;
    }
}


// /**
// FUNCTION    :: AtmAdaptationLayer5Finalize
// LAYER       :: Adaptation Layer
// PURPOSE     :: Finalize call for printing Aal5 statistics
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void
AtmAdaptationLayer5Finalize(Node* node)
{
    Aal5Data* aal5DataPtr = AalGetPtrForThisAtmNode(node);

    if (DEBUG)
    {
        Aal5PrintFwdTable(node);
        Aal5PrintTransTable(node);

        if (node->adaptationData.endSystem)
        {
            // connection table does not exist otherwise
            Aal5PrintConncTable(node);
            Aal5PrintAddrInfoTable(node, DEFAULT_INTERFACE);
        }
    }


    // Print out stats if user specifies it.
    if (node->adaptationData.adaptationStats)
    {
        char buf[MAX_STRING_LENGTH];

        sprintf(buf, "Number of AAL Service Data Units Sent = %d",
            aal5DataPtr->stats.numCpcsSduSent);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of AAL Service Data Units Received = %d",
            aal5DataPtr->stats.numCpcsSduRecv);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of ATM Service Data Units Sent = %d",
            aal5DataPtr->stats.numAtmSduSent);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of ATM Service Data Units Received = %d",
            aal5DataPtr->stats.numAtmSduRecv);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of ATM Service Data Units Dropped = %d",
            aal5DataPtr->stats.numAtmSduDropped);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Packets Segmented = %d",
            aal5DataPtr->stats.numPktSegmented);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Packets Reassembled = %d",
            aal5DataPtr->stats.numPktReassembled);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of SAAL Packets Sent = %d",
            aal5DataPtr->stats.numSaalPktSend);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of SAAL Packets Received = %d",
            aal5DataPtr->stats.numSaalPktRecvd);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Data Packets Sent = %d",
            aal5DataPtr->stats.numDataPktSend);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Data Packets Received = %d",
            aal5DataPtr->stats.numDataPktRecvd);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Data Packets Received from IP= %d",
            aal5DataPtr->stats.numPktFromIPNetwork);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Data Packets Forwarded to IP = %d",
            aal5DataPtr->stats.numPktFwdToIPNetwork);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of IP Packets Discarded = %d",
            aal5DataPtr->stats.numIpPktDiscarded);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of IP Packets Dropped = %d",
            aal5DataPtr->stats.numPktDroppedForNoRoute);
        IO_PrintStat(
            node,
            "Adaptation",
            "AAL5",
            ANY_DEST,
            -1, // instance Id,
            buf);
    }

    // SAAL Finalize to print End Simulation
    SaalFinalize(node);
    AtmRoutingStaticFinalize(node);
}

