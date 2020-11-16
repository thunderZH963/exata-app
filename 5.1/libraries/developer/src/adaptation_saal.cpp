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
// /**
// PROTOCOL     :: SAAL.
// LAYER        :: ADAPTATION.
// REFERENCES   ::
//              RFC: 2225 for Classical IP and ARP over ATM
//              RFC: 2684 for Multi-protocol Encapsulation over
//                 ATM Adaptation Layer 5
//              ATM Forum Addressing Specification:
//              Reference Guide AF-RA-0106.000
// COMMENTS     :: None
// **/
// **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "partition.h"
#include "mac_link.h"
#include "network_ip.h"
#include "adaptation_aal5.h"
#include "adaptation_saal.h"

#define DEBUG 0

// /**
// FUNCTION    :: SaalPrintAppList
// LAYER       :: Adaptation Layer
// PURPOSE     :: Print SAAL application list
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void SaalPrintAppList(Node* node)
{
    ListItem* item;
    Aal5Data*   aal5Data = AalGetPtrForThisAtmNode(node);
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    if (saalNodeData->appList->size)
    {
        printf(" # %u has in it's app List: \n", node->nodeId);
        printf("---------------------------------------------\n");
        printf(" VCI     VPI  outIntf   STATE    SRC     DST\n");

        item = saalNodeData->appList->first;

        while (item)
        {
            SaalAppData* saalAppData = (SaalAppData*) item->data;

            printf(" %d     %d     %d     %d       %x      %x \n",
                (saalAppData->VCI), saalAppData->VPI,
                saalAppData->outIntf, saalAppData->state,
                saalAppData->callingPartyNum->ESI_pt1,
                saalAppData->calledPartyNum->ESI_pt1);

            item = item->next;
        }//End while

        printf("\n \n");
    }
}


// /**
// FUNCTION    :: SaalGetDataForThisApp
// LAYER       :: Adaptation Layer
// PURPOSE     :: Search for a particular application
//                (denoted by VCI & VPI) in AppList
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : Virtual connection identifire.
// + VPI        : unsigned char :  VPI value for SAAL.
// RETURN       : SaalAppData* : Pointer to SAAL app data.
// **/
SaalAppData* SaalGetDataForThisApp(
    Node *node,
    unsigned short VCI,
    unsigned char VPI)
{
    ListItem* item;
    SaalAppData* entry;

    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    item =  saalNodeData->appList->first;

    while (item)
    {
        entry = (SaalAppData*) item->data;

        if (entry->VCI == VCI)
        {
            return entry;
        }
        item = item->next;
    }

    if (DEBUG)
    {
        printf("%u got an null SAAL for VCI %d & VPI %d \n",
            node->nodeId, VCI, VPI);
    }
    return NULL;
}


// /**
// FUNCTION    :: SaalResetVirtualPath
// LAYER       :: Adaptation Layer
// PURPOSE     :: Free all the network resources reserved for this connc
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// + intfId     : int : Interface identifire
// RETURN       : void : None
// **/
void SaalResetVirtualPath(
    Node* node,
    SaalAppData* saalAppData,
    int intfId)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    ListItem* item;
    BOOL isAdd;
    int incomingIntf;
    int outIntf;
    AtmBWInfo bwInfo;

    // Freed the associated BW
    isAdd = FALSE;
    incomingIntf = intfId;
    outIntf = intfId;
    bwInfo.vci = saalAppData->VCI;
    bwInfo.vpi = saalAppData->VPI;
    bwInfo.reqdBw = SAAL_DEFAULT_BW;

    if (Atm_BWCheck(node, incomingIntf, outIntf, isAdd, &bwInfo)== FALSE)
    {
        return;
    }

    // Reset the VPi List
    item = saalNodeData->saalIntf[intfId].vpiList->first;

    while (item)
    {
        SaalVPIListItem* thisEntry = (SaalVPIListItem*)item->data ;

        if (thisEntry->VCI == saalAppData->VCI)
        {
            // set that Virtual Path as IDLE
            thisEntry->status = SAAL_IDLE_PATH;
            return;
        }
        item = item->next;
    }
}


// /**
// FUNCTION    :: SaalFreeNetworkResources
// LAYER       :: Adaptation Layer
// PURPOSE     :: Free all the network resources reserved for this connc
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalFreeNetworkResources(Node* node, SaalAppData* saalAppData)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    if (DEBUG)
    {
        printf(" %u checking for freeing at intf %d for VCI %d\n",
            node->nodeId, saalAppData->outIntf, saalAppData->VCI);
    }

    // Remove item from the app list
    ListItem* item = saalNodeData->appList->first;

    while (item)
    {
        SaalAppData* thisSaalAppData = (SaalAppData*) item->data;

        if (thisSaalAppData->VCI == saalAppData->VCI)
        {
            // If I am not the end element for this connection
            // i.e. Destination or Termination point

            if (saalAppData->outIntf !=  SAAL_INVALID_INTERFACE)
            {
                if (DEBUG)
                {
                    printf(" %u freed BW at intf %d for VCI %d\n",
                        node->nodeId,
                        saalAppData->outIntf,
                        saalAppData->VCI);
                }
                SaalResetVirtualPath(node, thisSaalAppData,
                    saalAppData->outIntf);
            }

            if (DEBUG)
            {
                printf(" %u freed own AppList at intf %d for VCI %d\n",
                    node->nodeId, saalAppData->outIntf, saalAppData->VCI);
            }

            ListGet(node, saalNodeData->appList, item, TRUE, FALSE);

            return;
        }
        item = item->next;
    }//End while
}


// /**
// FUNCTION    :: SaalSupportForAvailableBandwidth
// LAYER       :: Adaptation Layer
// PURPOSE     :: Check if BW is available for this application
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// + outIntf    : int : interface thru which packet transfer
// RETURN       : unsigned char : Return the available VPI
// **/
unsigned char SaalSupportForAvailableBandwidth(Node* node,
                                               Message* msg,
                                               SaalAppData* saalAppData,
                                               int outIntf)
{
    // Need to chk if BW is supported for this VPI
    AtmBWInfo bwInfo;
    int incomingIntf;
    unsigned char outVPI = SAAL_INVALID_VPI;
    ListItem* item;

    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);

    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    SaalSetupPacket* setupPkt =
        (SaalSetupPacket*)MESSAGE_ReturnPacket(msg);

    // This is called during connection setup
    BOOL isAdd = TRUE;

    // At present, it is assumed all application
    // requires SAAL_DEFAULT_BW

    bwInfo.reqdBw = SAAL_DEFAULT_BW ;
    bwInfo.vci = saalAppData->VCI;
    bwInfo.vpi = saalAppData->VPI;

    incomingIntf = saalAppData->inIntf;

    // Ask ATM layer if BW available
    if (Atm_BWCheck(node, incomingIntf,outIntf, isAdd, &bwInfo) == FALSE)
    {

        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr,"%u: BW does not support for VCI %d\n",
                node->nodeId, saalAppData->VCI);
        ERROR_ReportWarning(errStr);

        return outVPI;
    }

    if (DEBUG)
    {
        printf(" Node %u BW supported for VCI %d\n",
            node->nodeId, saalAppData->VCI);
    }

    // Search for available virtual Path
    // First check through the available list

    item = saalNodeData->saalIntf[outIntf].vpiList->first;
    while (item)
    {
        SaalVPIListItem* thisEntry = (SaalVPIListItem*)item->data ;
        if (thisEntry->status == SAAL_IDLE_PATH)
        {
            // allocate this VPI for present application
            thisEntry->status = SAAL_BUSY_PATH;
            thisEntry->VCI = saalAppData->VCI;

            // TBD: if BW varies this part need to be changed
            thisEntry->pathBW = bwInfo.reqdBw;

            outVPI = (unsigned char)thisEntry->virPathId;
            saalAppData->finalVPI = outVPI;
            setupPkt->conncId.VPI = outVPI;

            return outVPI;
        }
        item = item->next;
    }

    // If maxVPI are not used then create new item in list
    if (saalNodeData->saalIntf[outIntf].numVPI <
        saalNodeData->saalIntf[outIntf].maxVPI)
    {
        SaalVPIListItem* newEntry =
            (SaalVPIListItem*)MEM_malloc(sizeof(SaalVPIListItem));

        // If not found any idle path create one.
        saalNodeData->saalIntf[outIntf].numVPI++;

        newEntry->status = SAAL_BUSY_PATH;
        newEntry->VCI = saalAppData->VCI;
        newEntry->virPathId = saalNodeData->saalIntf[outIntf].numVPI;
        newEntry->pathBW = bwInfo.reqdBw;

        // Insert Item in the list
        ListInsert(node,
            saalNodeData->saalIntf[outIntf].vpiList,
            0,
            (void*) newEntry);

        // final VPI need to be set
        outVPI = (unsigned char) newEntry->virPathId;
        saalAppData->finalVPI = outVPI;
        setupPkt->conncId.VPI = outVPI;

        return outVPI;

    } // If max VPI is still not used;

    // final VPI need to be set
    saalAppData->finalVPI = outVPI;
    setupPkt->conncId.VPI = outVPI;

    if (DEBUG)
    {
        printf(" For node %u BW is not supported \n", node->nodeId);
        SaalPrintAppList(node);
    }
    return outVPI;
}


// /**
// FUNCTION    :: SaalCheckEndPointType(
// LAYER       :: Adaptation Layer
// PURPOSE     :: check if I am U-UNI or N-NNI on calling
//                side or called side
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCheckEndPointType(Node* node, SaalAppData* saalAppData)
{

    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);

    // Check the END-POINT-TYPE
    // i.e. if I am (N-UNI)/(U-UNI) on sender side
    // or I am (N-UNI)/(U-UNI) on destination side.

    //if I am the source then I am U-UNI on sender side
    if ((saalAppData->callingPartyNum->ESI_pt1
        == aal5Data->atmRouterId.ESI_pt1)
        &&(saalAppData->callingPartyNum->ESI_pt2
        == aal5Data->atmRouterId.ESI_pt2))
    {
        saalAppData->endPointType = CALLING_USER;
        return;
    }

    // Then check if I am the dest

    // If called party num is not properly specified
    // and I am an end-system but not caaling_user
    // then treated as destination.

    if ((saalAppData->calledPartyNum->AFI == 0
        && node->adaptationData.endSystem)
        || (saalAppData->calledPartyNum->ESI_pt1
        == aal5Data->atmRouterId.ESI_pt1
        && saalAppData->calledPartyNum->ESI_pt2
        == aal5Data->atmRouterId.ESI_pt2))
    {
        saalAppData->endPointType = CALLED_USER;
    }

    //if they are one hop away both from Src & Dest
    else if ((AalCheckIfItIsInAttachedNetwork(node,
                saalAppData->callingPartyNum))
        && (AalCheckIfItIsInAttachedNetwork(node,
                saalAppData->calledPartyNum)))
    {
        saalAppData->endPointType = COMMON_NET_SWITCH;
    }

    //if source is one hop away then I am N-UNI on sender side
    else if (AalCheckIfItIsInAttachedNetwork(node,
        saalAppData->callingPartyNum))
    {
        saalAppData->endPointType = CALLING_NET_SWITCH;
    }

    //if dest is one hop away then I am N-UNI on destination side
    else if (AalCheckIfItIsInAttachedNetwork(node,
        saalAppData->calledPartyNum))
    {
        saalAppData->endPointType = CALLED_NET_SWITCH;
    }
    else
    {
        saalAppData->endPointType = NORMAL_POINT;
    }
}


// /**
// FUNCTION    :: SaalCheckForSupportOfIE
// LAYER       :: Adaptation Layer
// PURPOSE     :: Check if all the necessary IE are present in Setup Msg
//                & they are valid
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : BOOL : Yes if suppoter else No
// **/
BOOL SaalCheckForSupportOfIE(
    Node* node,
    Message* msg,
    SaalAppData* saalAppData)
{
    BOOL supportVal = FALSE;

    SaalSetupPacket* setupPkt =
        (SaalSetupPacket*)MESSAGE_ReturnPacket(msg);

    // check if all the necessary info are available
    if ((!setupPkt->aalIE.AALType)
        || (!&setupPkt->calledPartyNum.CalledPartyNum)
        || (!&setupPkt->callingPartyNum.CallingPartyNum)
        || (!setupPkt->conncId.VCI))
    {
        supportVal = FALSE;
        return supportVal;
    }

    // TBD:
    // Checks if it supports all the IE parameters of
    // setup e.g. AAL, QoS, BW & other such parameters
    // presently only AAl type is checked

    if (setupPkt->aalIE.AALType != ADAPTATION_PROTOCOL_AAL5)
    {
        supportVal = FALSE;
    }
    else
    {
        supportVal = TRUE;
    }

    return supportVal;
}


// /**
// FUNCTION    :: SaalUpdateTransTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Create/Modify entry in Forwarding table
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + entry      : SaalAppData* : Pointer to SAAL app data.
// + intfId     : int : Interface identifire
// RETURN       : void : None
// **/
void SaalUpdateTransTable(
    Node* node,
    SaalAppData* entry,
    int intfId)
{
    unsigned short VCI = entry->VCI;
    unsigned char VPI = entry->VPI;
    unsigned char finalVPI = entry->finalVPI;
    int outIntf = entry->outIntf;

    if (DEBUG)
    {
        printf(" Node %u updating outVPI %d\n",
            node->nodeId, finalVPI);
    }

    Aal5UpdateTransTable(node, VCI, VPI, finalVPI, outIntf);
}


// /**
// FUNCTION    :: SaalSetNewSession
// LAYER       :: Adaptation Layer
// PURPOSE     :: Create a new entry in app list to store
//                this application related information
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + clientAddr : Address : client for this application
// + serverAddr : Address : server for this Application
// + entryPoint : AtmAddress* : entry point to ATM cloud
// + exitPoint  : AtmAddress* : exit point from ATM cloud
// + prevHop    : AtmAddress* : prevHop Address for this entry
// + intfId     : int : Interface identifire
// + VCI        : unsigned short : Virtual connection identifire.
// + VPI        : unsigned char :  VPI value for SAAL.
// RETURN       : void : None
// **/
void SaalSetNewSession(Node *node,
                       Address clientAddr,
                       Address serverAddr,
                       AtmAddress* entryPoint,
                       AtmAddress* exitPoint,
                       AtmAddress* prevHop,
                       int inIntf,
                       unsigned short VCI,
                       unsigned char VPI)
{
    SaalAppData* newEntry;

    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    newEntry = (SaalAppData*) MEM_malloc(sizeof(SaalAppData));
    memset(newEntry, 0, sizeof(SaalAppData));

    newEntry->state = SAAL_NULL;

     // Note down the client & server address
    newEntry->callingPartyAddr = clientAddr;
    newEntry->calledPartyAddr = serverAddr;

    // Note down the ATM cloud entry point & exit point
    newEntry->callingPartyNum =
        (AtmAddress*) MEM_malloc(sizeof(AtmAddress));

    memcpy(newEntry->callingPartyNum,
        entryPoint, sizeof(AtmAddress));

    newEntry->calledPartyNum =
        (AtmAddress*) MEM_malloc(sizeof(AtmAddress));

    memcpy(newEntry->calledPartyNum,
        exitPoint, sizeof(AtmAddress));

    // all timer related info will be stored here
    // at present it is kept empty
    ListInit(node, &newEntry->timerList);

    newEntry->VCI = VCI;
    newEntry->VPI = VPI;
    newEntry->inIntf = inIntf;

    // final VPI will be set if the connection establised
    // & it reaches to the active state
    newEntry->finalVPI = SAAL_INVALID_VPI;

    newEntry->prevHopAddr =
        (AtmAddress*) MEM_malloc(sizeof(AtmAddress));

    memcpy(newEntry->prevHopAddr,
        prevHop, sizeof(AtmAddress));

    newEntry->nextHopAddr =
        (AtmAddress*) MEM_malloc(sizeof(AtmAddress));

    // set out intf & nextHop
    AalGetOutIntfAndNextHopForDest(node,
        newEntry->calledPartyNum,
        &newEntry->outIntf,
        newEntry->nextHopAddr);

    // set endPoint Type
    SaalCheckEndPointType(node, newEntry);

    // Insert a new item in appList
    ListInsert(node, saalNodeData->appList, 0, (void*)newEntry);
}


// /**
// FUNCTION    :: SaalCreateCommonHeader
// LAYER       :: Adaptation Layer
// PURPOSE     :: Create Header for Saal control Message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + pktHdr     : SaalMsgHeader* : Pointer to message header
// + type       : SaalMsgType : SAAL message type.
// + ieLength   : int : Information elemnt header length
// RETURN       : void : None
// **/
void SaalCreateCommonHeader(
    Node* node,
    SaalMsgHeader* pktHdr,
    SaalMsgType type,
    int ieLength)
{

    // REF: Q.2931 ITU-T Statndard
    // 00001001 ->Q.2931 user-network call/connc control messages

    pktHdr->protocolDisclaimer = RROTOCOL_DISCLAIMER;

    pktHdr->callRefLength = 3; //In Octet;
    SaalMsgHeaderSetRefVal(&(pktHdr->saalMsgHdr), 1);

    //The originating side always sets the call reference flag to 0.
    //The destination side always sets the call reference flag to 1.

    SaalMsgHeaderSetFlag(&(pktHdr->saalMsgHdr), FALSE);

    pktHdr->callRefValue2 = 1;
    pktHdr->messageType = type;
    pktHdr->messageType1 = 0; // spare so kept as 0;
    pktHdr->messageLength = (short)ieLength;

}

// /**
// FUNCTION    :: SaalStopsTimer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Cancel the message pointer for this self-timer
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// + intfId     : int : Interface identifire
// + type       : SaalTimerType : The type of Timer used
// RETURN       : void : None
// **/
void SaalStopsTimer(Node* node,
                    SaalAppData* saalAppData,
                    int intfId,
                    SaalTimerType type)
{
    ListItem* item;
    SaalTimerData* timerData;

    //seach associated list
    item = saalAppData->timerList->first;

    //check for matching timerData
    while (item)
    {
        timerData = (SaalTimerData*) item->data;

        if ((timerData->type == type)
            && (timerData->intfId == intfId))
        {
            // Matching Entry Found
            Message* thisTimerPtr =
                (Message*)timerData->timerPtr;

            if (thisTimerPtr->cancelled == TRUE)
            {
                if (DEBUG)
                {
                    printf("Timer type %d at %u is cancelled\n",
                        timerData->type,node->nodeId);
                }
            }
            else
            {
                if (DEBUG)
                {
                    printf(" %u -stop Timer %d at intf %d\n",
                        node->nodeId, timerData->type,
                        timerData->intfId);
                }

                MESSAGE_CancelSelfMsg(node, (Message*)thisTimerPtr);

                ListGet(node,
                    saalAppData->timerList,
                    item, TRUE, FALSE);
            }
            return;
        }
        item = item->next;
    }

    if (DEBUG)
    {
        printf(" %u VCI %d Timer %d at intf %d is not created/freed\n",
            node->nodeId, saalAppData->VCI, type, intfId);
    }
}


// /**
// FUNCTION    :: SaalStartTimer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Allocate & Send Self Timer for SAAL
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + timer      : SaalTimerData* : Pointer to timer data.
// + delay      : clocktype : delay to fire that Timer.
// + eventType  : int : Required event type
// RETURN       : char* : pointer to this timer message
// **/
char* SaalStartTimer(
    Node* node,
    SaalTimerData* timer,
    clocktype delay,
    int eventType)
{
    char* msgPtr = NULL;
    SaalTimerData* msgTimerInfo ;

    Message* newMsg = MESSAGE_Alloc(node,
        ADAPTATION_LAYER,
        ATM_PROTOCOL_SAAL,
        eventType);

    MESSAGE_InfoAlloc(node, newMsg,  sizeof(SaalTimerData));

    msgTimerInfo = (SaalTimerData*) MESSAGE_ReturnInfo(newMsg);
    memcpy(msgTimerInfo, timer, sizeof(SaalTimerData));

    msgPtr = (char*)newMsg;

    if (DEBUG)
    {
    printf(" Node %u starts timer %d at intf %d \n",
        node->nodeId, timer->type, timer->intfId);

    }
    MESSAGE_Send(node, (Message*)newMsg, delay);
    return (char*)msgPtr;
}


// /**
// FUNCTION    :: SaalFillCommonIEPart
// LAYER       :: Adaptation Layer
// PURPOSE     :: Fill the common part of IE header part
//                for each information element in a message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + type       : unsigned char : type of IE identifier
// + ieFieldPtr : void* : Informatiuon field pointer
// + thisIEContentLn : int : Information element length
// RETURN       : void : None
// **/
void SaalFillCommonIEPart(
    Node* node,
    unsigned char type,
    void* ieFieldPtr,
    int thisIEContentLn)
{
    memset(ieFieldPtr, 0, thisIEContentLn);

    SaalInformationElement* ieHeader =
        (SaalInformationElement*)ieFieldPtr;

    ieHeader->IE_identifier= type;
    ieHeader->IE_contentLn =
        (short)(thisIEContentLn- sizeof(SaalInformationElement));
}


// /**
// FUNCTION    :: SaalUpdateTimerList
// LAYER       :: Adaptation Layer
// PURPOSE     :: Saal search for matching timer
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// + intfId     : int : Interface identifire
// + type       : SaalTimerType : type of Saal timer used
// RETURN       : SaalTimerData* : Pointer to SAAL tiomer data.
// **/
SaalTimerData* SaalUpdateTimerList(
    Node* node,
    SaalAppData *saalAppData,
    int intfId,
    SaalTimerType type)
{
    ListItem* item;
    SaalTimerData* timerData;

    //seach associated list
    item = saalAppData->timerList->first;

    //check for matching timerData
    while (item)
    {
        timerData = (SaalTimerData*) item->data;

        if ((timerData->type == type)
            && (timerData->intfId == intfId))
        {
            // Matching Entry Found
            timerData->seqNo++;

            return timerData;
        }
        item = item->next;
    }

    // No matching entry found
    // insert an item

    timerData = (SaalTimerData*)
        MEM_malloc(sizeof(SaalTimerData));

    memset(timerData, 0, sizeof(SaalTimerData));

    timerData->intfId = intfId;
    timerData->type = type;
    timerData->VCI = saalAppData->VCI;
    timerData->VPI = saalAppData->VPI;
    timerData->seqNo = 1;

    ListInsert(node, saalAppData->timerList, 0, (void*)timerData);

    return timerData;
}



// /**
// FUNCTION    :: SaalSendReleaseMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Create & send Release message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
static
void SaalSendReleaseMessage(
    Node* node,
    SaalAppData* saalAppData)
{
    Message* releaseMsg = NULL;
    SaalReleasePacket* releasePacket = NULL;
    signed int outIntf;
    AtmAddress nextHop ;
    int ieLength;
    Aal5Data*   aal5Data =  NULL;
    Aal5InterfaceData* atmIntf =  NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // Create setup Messasge
    releaseMsg = MESSAGE_Alloc(node,
        ADAPTATION_LAYER,
        ATM_PROTOCOL_SAAL,
        MSG_ATM_ADAPTATION_SaalPacket);

    MESSAGE_PacketAlloc(node,
        releaseMsg,
        sizeof(SaalReleasePacket),
        TRACE_SAAL);

    releasePacket = (SaalReleasePacket*)
        MESSAGE_ReturnPacket(releaseMsg);

    // Fill in the setup packet related IE -Common Part
    SaalFillCommonIEPart(node, SAAL_IE_CONNC_ID,
        &(releasePacket->conncId), sizeof(SaalIEConncIdentifier));

    // Fill in the setup packet related IE - Specific Part
    releasePacket->conncId.VCI = saalAppData->VCI;
    releasePacket->conncId.VPI = saalAppData->VPI;

    ieLength = releasePacket->conncId.ieField.IE_contentLn +
        sizeof(SaalInformationElement);

    // Fill in the header fields for the releaseMsg
    SaalCreateCommonHeader(node,
        &releasePacket->header, SAAL_RELEASE, ieLength);

    // NextHop & outgoing Interface for the nearest network element
    outIntf = saalAppData->outIntf;
    memcpy(&nextHop, saalAppData->nextHopAddr, sizeof(AtmAddress));

    // send packet to the nearest switch elemenet or called party
    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, releaseMsg),
        &(atmIntf[outIntf].atmIntfAddr),
        saalAppData->calledPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_RELEASE);

    MESSAGE_Free(node, releaseMsg);
    saalNodeData->stats.NumOfAtmReleaseSent++;
}


// /**
// FUNCTION    :: SaalTerminateConnection
// LAYER       :: Adaptation Layer
// PURPOSE     :: Saal can terminate connection for resource unavialability
//                or end time arrived & send release
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalTerminateConnection(
    Node* node,
    SaalAppData* saalAppData)
{
    if (DEBUG)
    {
        printf(" #%u  is ready for closing connc\n",
            node->nodeId);
    }

    SaalSendReleaseMessage(node, saalAppData);

    // starts Timer T306
    SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
        saalAppData, saalAppData->outIntf, SAAL_TIMER_T306);

    // Fire the Timer
    timerData->timerPtr = SaalStartTimer(node,
        timerData,
        SAAL_TIMER_T306_DELAY,
        MSG_ATM_ADAPTATION_SaalT306Timer);

    // changes state to Release Request
    saalAppData->state = SAAL_RELEASE_REQUEST;
}


// /**
// FUNCTION    :: SaalForwardingSetupMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Forwarding Setup message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalForwardingSetupMessage(
    Node* node,
    Message* msg,
    SaalAppData* saalAppData)
{
    int outIntf;
    AtmAddress nextHop ;

    Aal5Data*   aal5Data =  AalGetPtrForThisAtmNode(node);

    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // NextHop & outgoing Interface for the nearest network element
    AalGetOutIntfAndNextHopForDest(node,
        saalAppData->calledPartyNum, &outIntf, &nextHop);

    if (outIntf ==  SAAL_INVALID_INTERFACE)
    {
        // Routes not available for this destination
        // Hence route the packet thru all interface

        int i;

        for (i = 0; i < node->numAtmInterfaces; i++)
        {
            // Avoid sending sendup to myself
            if (i == saalAppData->inIntf)
            {
                // skip that interface
                continue;
            }

            // get nextHop
            Address nextHopAddr =
                Atm_GetAddrForOppositeNodeId(node, i);

            memcpy(&nextHop,
                &nextHopAddr.interfaceAddr.atm,
                sizeof(AtmAddress));

            // Check for BW Availability
            if (SaalSupportForAvailableBandwidth(node, msg,
                saalAppData, i) != SAAL_INVALID_VPI)
            {
                // Available BW support this connection
                 if (DEBUG)
                {
                    SaalSetupPacket* setupPkt =
                        (SaalSetupPacket*)MESSAGE_ReturnPacket(msg);

                    printf(" Node %u: sending setup thru intf %d \n",
                        node->nodeId, i);

                    printf("VCI %d and VPI %d \n",
                        setupPkt->conncId.VCI,
                        setupPkt->conncId.VPI);
                }

                // Send Setup
                AalSendSignalingMsgToLinkLayer(
                    node,
                    MESSAGE_Duplicate(node, msg),
                    saalAppData->callingPartyNum,
                    saalAppData->calledPartyNum,
                    AAL_SAAL_TTL,
                    i,
                    &nextHop,
                    SAAL_SETUP);

                saalNodeData->stats.NumOfAtmSetupSent++;

                // Start timer T303
                SaalTimerData*  timerData;

                // Search for matching entry from Timer List
                timerData = SaalUpdateTimerList(node,
                    saalAppData, i, SAAL_TIMER_T303);

                // Fire the Timer
                timerData->timerPtr = SaalStartTimer(node,
                    timerData,
                    SAAL_TIMER_T303_DELAY,
                    MSG_ATM_ADAPTATION_SaalT303Timer);

            }
        } //end of for
    } //if network_unreachable
    else
    {
        // Check for BW Availability
        if (SaalSupportForAvailableBandwidth(node, msg,
            saalAppData, outIntf) != SAAL_INVALID_VPI)
        {
            // Available BW support this connection
            // Set entry's outgoing parametr accordingly
            saalAppData->outIntf = outIntf;
            memcpy(saalAppData->nextHopAddr,
                &nextHop, sizeof(AtmAddress));

            if (DEBUG)
            {
                printf(" Node %u: sending setup thru intf %d \n",
                    node->nodeId, outIntf);
            }

            // Send Setup
            AalSendSignalingMsgToLinkLayer(
                node,
                MESSAGE_Duplicate(node, msg),
                saalAppData->callingPartyNum,
                saalAppData->calledPartyNum,
                AAL_SAAL_TTL,
                outIntf,
                &nextHop,
                SAAL_SETUP);

            saalNodeData->stats.NumOfAtmSetupSent++;

            // Start timer T303
            SaalTimerData*  timerData;

            // Search for matching entry from Timer List
            timerData = SaalUpdateTimerList(node,
                saalAppData, outIntf, SAAL_TIMER_T303);

            // Fire the Timer
            timerData->timerPtr = SaalStartTimer(node,
                timerData,
                SAAL_TIMER_T303_DELAY,
                MSG_ATM_ADAPTATION_SaalT303Timer);
        }
    }
}


// /**
// FUNCTION    :: SaalSendSetupMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Create & send Setup message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
static
void SaalSendSetupMessage(
    Node* node,
    SaalAppData* saalAppData)
{
    Message* setupMsg = NULL;
    SaalSetupPacket* setupPacket = NULL;
    int ieLength;
    Aal5Data*   aal5Data =  NULL;
    Aal5InterfaceData* atmIntf =  NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    // Create setup Messasge
    setupMsg = MESSAGE_Alloc(node,
        ADAPTATION_LAYER,
        ATM_PROTOCOL_SAAL,
        MSG_ATM_ADAPTATION_SaalPacket);

    MESSAGE_PacketAlloc(node,
        setupMsg,
        sizeof(SaalSetupPacket),
        TRACE_SAAL);

    setupPacket = (SaalSetupPacket*)
        MESSAGE_ReturnPacket(setupMsg);

    // Fill in the setup packet related IE -Common Part
    SaalFillCommonIEPart(node, SAAL_IE_AALPARAM,
        &(setupPacket->aalIE), sizeof(SaalIEAALParameters));

    SaalFillCommonIEPart(node, SAAL_IE_ATM_TR_DESC,
        &(setupPacket->trDesc), sizeof(SaalIEATMTrDescriptor));

    SaalFillCommonIEPart(node, SAAL_IE_BROAD_BR_CAP,
        &(setupPacket->brBearerCap),
        sizeof(SaalIEBrBearerCapability));

    SaalFillCommonIEPart(node, SAAL_IE_BROAD_LLAYER_INFO,
        &(setupPacket->brLowLayerInfo),
        sizeof(SaalIEBrLowLayerInfo));

    SaalFillCommonIEPart(node, SAAL_IE_CALLED_PARTY_NUM,
        &(setupPacket->calledPartyNum),
        sizeof(SaalIECalledPartyNumber));

    SaalFillCommonIEPart(node, SAAL_IE_CALLING_PARTY_NUM,
        &(setupPacket->callingPartyNum),
        sizeof(SaalIECallingPartyNumber));

    SaalFillCommonIEPart(node, SAAL_IE_CALLING_PARTY_SUBADDRESS,
        &(setupPacket->callingPartyAddr),
        sizeof(SaalIECallingPartySubAddr));

    SaalFillCommonIEPart(node, SAAL_IE_CALLED_PARTY_SUBADDRESS,
        &(setupPacket->calledPartyAddr),
        sizeof(SaalIECalledPartySubAddr));

    SaalFillCommonIEPart(node, SAAL_IE_CONNC_ID,
        &(setupPacket->conncId), sizeof(SaalIEConncIdentifier));

    SaalFillCommonIEPart(node, SAAL_IE_QOS_PARAM,
        &(setupPacket->conncId),
        sizeof(SaalIEQOSParameter));

    // Fill in the setup packet related IE - Specific Part
    setupPacket->aalIE.AALType = ADAPTATION_PROTOCOL_AAL5;

    // It is assumed that each application requires default_BW
    setupPacket->qosParam.qosClass = SAAL_DEFAULT_BW;

    // Note down the ATM cloud entry point & exit point
    memcpy(&(setupPacket->callingPartyNum.CallingPartyNum),
        saalAppData->callingPartyNum, sizeof(AtmAddress));

    memcpy(&(setupPacket->calledPartyNum.CalledPartyNum),
        saalAppData->calledPartyNum, sizeof(AtmAddress));

    // Note down the application Src & Dest Address
    memcpy(&setupPacket->callingPartyAddr.callingPartyAddr,
        &saalAppData->callingPartyAddr,
        sizeof(Address));

    memcpy(&setupPacket->calledPartyAddr.calledPartyAddr,
        &saalAppData->calledPartyAddr,
        sizeof(Address));

    // set up connection ID
    setupPacket->conncId.VCI = saalAppData->VCI;
    setupPacket->conncId.VPI = saalAppData->VPI;

    ieLength = setupPacket->aalIE.ieField.IE_contentLn +
        setupPacket->trDesc.ieField.IE_contentLn +
        setupPacket->brBearerCap.ieField.IE_contentLn +
        setupPacket->brLowLayerInfo.ieField.IE_contentLn +
        setupPacket->calledPartyNum.ieField.IE_contentLn +
        setupPacket->callingPartyNum.ieField.IE_contentLn +
        setupPacket->calledPartyAddr.ieField.IE_contentLn +
        setupPacket->callingPartyAddr.ieField.IE_contentLn +
        setupPacket->conncId.ieField.IE_contentLn +
        ((sizeof(SaalInformationElement)) * 9);

    // Fill in the header fields for the SetupMsg
    SaalCreateCommonHeader(node,
        &setupPacket->header, SAAL_SETUP, ieLength);

    SaalForwardingSetupMessage(node, setupMsg, saalAppData);

    MESSAGE_Free(node, setupMsg);
}


// /**
// FUNCTION    :: SaalSendReleaseCompleteMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Create & send Release Complete message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
static
void SaalSendReleaseCompleteMessage(
    Node* node,
    SaalAppData* saalAppData)
{
    Message* releaseComplMsg = NULL;
    SaalReleaseCompletePacket* releaseComplPacket = NULL;
    int outIntf;
    AtmAddress nextHop ;
    int ieLength;
    Aal5Data*   aal5Data =  NULL;
    Aal5InterfaceData* atmIntf =  NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // Create Release Complete Messasge
    releaseComplMsg = MESSAGE_Alloc(node,
        ADAPTATION_LAYER,
        ATM_PROTOCOL_SAAL,
        MSG_ATM_ADAPTATION_SaalPacket);

    MESSAGE_PacketAlloc(node,
        releaseComplMsg,
        sizeof(SaalReleaseCompletePacket),
        TRACE_SAAL);

    releaseComplPacket = (SaalReleaseCompletePacket*)
        MESSAGE_ReturnPacket(releaseComplMsg);

    // Fill in the release Complete packet related IE
    // Common Part
    SaalFillCommonIEPart(node, SAAL_IE_CONNC_ID,
        &(releaseComplPacket->conncId),
        sizeof(SaalIEConncIdentifier));

    // Specific Part
    releaseComplPacket->conncId.VCI = saalAppData->VCI;
    releaseComplPacket->conncId.VPI = saalAppData->VPI;

    ieLength = releaseComplPacket->conncId.ieField.IE_contentLn +
        sizeof(SaalInformationElement);

    // Fill in the header fields for the release complMsg
    SaalCreateCommonHeader(node,
        &releaseComplPacket->header,
        SAAL_RELEASE_COMPLETE, ieLength);

    outIntf = saalAppData->inIntf;
    memcpy(&nextHop, saalAppData->prevHopAddr, sizeof(AtmAddress));

    // send packet to the nearest switch elemenet or called party
    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, releaseComplMsg),
        &(atmIntf[outIntf].atmIntfAddr),
        saalAppData->callingPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_RELEASE_COMPLETE);

    MESSAGE_Free(node, releaseComplMsg);
    saalNodeData->stats.NumOfAtmReleaseCompleteSent++;
}



// /**
// FUNCTION    :: SaalSendCallProceedingMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Send Call Proceedings Message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
static
void SaalSendCallProceedingMessage(
    Node* node,
    SaalAppData* saalAppData)
{
    Message* callProcMsg = NULL;
    SaalCallProcPacket* callProcPacket = NULL;
    int outIntf;
    AtmAddress nextHop;
    int ieLength;
    Aal5Data*   aal5Data;
    Aal5InterfaceData* atmIntf;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    callProcMsg = MESSAGE_Alloc(node,
        ADAPTATION_LAYER,
        ATM_PROTOCOL_SAAL,
        MSG_ATM_ADAPTATION_SaalPacket);

    MESSAGE_PacketAlloc(node,
        callProcMsg,
        sizeof(SaalCallProcPacket),
        TRACE_SAAL);

    callProcPacket = (SaalCallProcPacket*)
        MESSAGE_ReturnPacket(callProcMsg);

    // Send to the AES from which it receives the SETUP
    outIntf = saalAppData->inIntf;
    memcpy(&nextHop, saalAppData->prevHopAddr, sizeof(AtmAddress));

    //Fill in the CallProceedingMsg packet related IE
    // Common Part

    SaalFillCommonIEPart(node, SAAL_IE_CONNC_ID,
        &(callProcPacket->conncId), sizeof(SaalIEConncIdentifier));

    // Specific part
    callProcPacket->conncId.VCI = saalAppData->VCI;
    callProcPacket->conncId.VPI = saalAppData->VPI;

    ieLength = callProcPacket->conncId.ieField.IE_contentLn +
        sizeof(SaalInformationElement);

    // Fill in the header fields for the CallProceedingMsg
    // ieLength = Sizeof(total length of information element;
    SaalCreateCommonHeader(node,
        &(callProcPacket->header), SAAL_CALL_PROCEEDING, ieLength);

    AalSendSignalingMsgToLinkLayer (
        node,
        MESSAGE_Duplicate(node, callProcMsg),
        &(atmIntf[outIntf].atmIntfAddr),
        saalAppData->prevHopAddr,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_CALL_PROCEEDING);

    MESSAGE_Free(node, callProcMsg);
    saalNodeData->stats.NumOfAtmCallProcSent++;
}


// /**
// FUNCTION    :: SaalSendAlertingMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Send Alert message during connection setup
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
static
void SaalSendAlertingMessage(Node* node, SaalAppData* saalAppData)
{
    Message* alertMsg = NULL;
    SaalAlertPacket* alertPacket = NULL;
    int outIntf;
    AtmAddress nextHop;

    int ieLength;
    Aal5Data*   aal5Data =  NULL;
    Aal5InterfaceData* atmIntf =  NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // Create alert Messasge
    alertMsg = MESSAGE_Alloc(node,
        ADAPTATION_LAYER,
        ATM_PROTOCOL_SAAL,
        MSG_ATM_ADAPTATION_SaalPacket);

    MESSAGE_PacketAlloc(node,
        alertMsg,
        sizeof(SaalAlertPacket),
        TRACE_SAAL);

    alertPacket = (SaalAlertPacket*)
        MESSAGE_ReturnPacket(alertMsg);

    // NextHop & outgoing Interface for the nearest network element
    // i.e. back to the point from where it received setup

    outIntf = saalAppData->inIntf;
    memcpy(&nextHop, saalAppData->prevHopAddr, sizeof(AtmAddress));

    // Fill in the alert packet related parameter
    // common part

    SaalFillCommonIEPart(node, SAAL_IE_CONNC_ID,
        &(alertPacket->conncId), sizeof(SaalIEConncIdentifier));

    SaalFillCommonIEPart(node, SAAL_IE_CALLED_PARTY_NUM,
        &(alertPacket->calledPartyNum),
        sizeof(SaalIECalledPartyNumber));

    // specific part : connection Id
    alertPacket->conncId.VCI = saalAppData->VCI;
    alertPacket->conncId.VPI = saalAppData->VPI;

    // specific part : called Party Num
    memcpy(&(alertPacket->calledPartyNum.CalledPartyNum),
        saalAppData->calledPartyNum, sizeof(AtmAddress));

    ieLength = alertPacket->conncId.ieField.IE_contentLn +
        alertPacket->calledPartyNum.ieField.IE_contentLn +
        sizeof(SaalInformationElement);

    // Fill in the header fields for the Alert Msg
    SaalCreateCommonHeader(node,
        &alertPacket->header, SAAL_ALERT, ieLength);

    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, alertMsg),
        saalAppData->calledPartyNum,
        saalAppData->callingPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_ALERT);

    MESSAGE_Free(node, alertMsg);
    saalNodeData->stats.NumOfAtmAlertSent++;
}


// /**
// FUNCTION    :: SaalSendConnectMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Send Connect Message during connection setup
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
static
void SaalSendConnectMessage(Node* node, SaalAppData* saalAppData)
{
    Message* connectMsg = NULL;
    SaalConnectPacket* connectPacket = NULL;
    int outIntf;
    AtmAddress nextHop;
    int ieLength;
    Aal5Data*   aal5Data =  NULL;
    Aal5InterfaceData* atmIntf =  NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // Create connect Messasge
    connectMsg = MESSAGE_Alloc(node,
        ADAPTATION_LAYER,
        ATM_PROTOCOL_SAAL,
        MSG_ATM_ADAPTATION_SaalPacket);

    MESSAGE_PacketAlloc(node,
        connectMsg,
        sizeof(SaalConnectPacket),
        TRACE_SAAL);

    connectPacket = (SaalConnectPacket*)
        MESSAGE_ReturnPacket(connectMsg);

    // Fill in the Connect Msg related IE
    // Common Part

    SaalFillCommonIEPart(node, SAAL_IE_AALPARAM,
        &(connectPacket->aalIE),
        sizeof(SaalIEAALParameters));

    SaalFillCommonIEPart(node, SAAL_IE_BROAD_LLAYER_INFO,
        &(connectPacket->brLowLayerInfo),
        sizeof(SaalIEBrLowLayerInfo));

    SaalFillCommonIEPart(node, SAAL_IE_CONNC_ID,
        &(connectPacket->conncId),
        sizeof(SaalIEConncIdentifier));

    SaalFillCommonIEPart(node, SAAL_IE_END_TO_END_DELAY,
        &(connectPacket->endToEndDelay),
        sizeof(SaalIEEndToEndDelay));

    // Specific part
    connectPacket->aalIE.AALType = ADAPTATION_PROTOCOL_AAL5;
    connectPacket->conncId.VCI = saalAppData->VCI;
    connectPacket->conncId.VPI = saalAppData->VPI;

    ieLength = connectPacket->aalIE.ieField.IE_contentLn +
        connectPacket->brLowLayerInfo.ieField.IE_contentLn +
        connectPacket->conncId.ieField.IE_contentLn +
        connectPacket->endToEndDelay.ieField.IE_contentLn +
        (sizeof(SaalInformationElement) * 4);

    // Fill in the header fields for the ConnectMsg
    SaalCreateCommonHeader(node,
        &connectPacket->header, SAAL_CONNECT, ieLength);

    // NextHop & outgoing Interface for the
    // nearest network element

    outIntf = saalAppData->inIntf;
    memcpy(&nextHop, saalAppData->prevHopAddr, sizeof(AtmAddress));

    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, connectMsg),
        &(atmIntf[outIntf].atmIntfAddr),
        saalAppData->callingPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_CONNECT);

    MESSAGE_Free(node, connectMsg);
    saalNodeData->stats.NumOfAtmConnectSent++;
}


// /**
// FUNCTION    :: SaalSendConnectAcknowledgeMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Send ConnectAcknowledgeMessage after
//                receiving connect message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + prevHop    : AtmAddress* : Pointer to previous hop
// + interfaceIndex : int : Interface index
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
static
void SaalSendConnectAcknowledgeMessage(
    Node* node,
    AtmAddress* prevHop,
    int interfaceIndex,
    SaalAppData* saalAppData)
{
    Message* connectAckMsg = NULL;
    SaalConnectAckPacket* connectAckPacket = NULL;
    int outIntf;
    AtmAddress nextHop;
    int ieLength;
    Aal5Data*   aal5Data =  NULL;
    Aal5InterfaceData* atmIntf =  NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // Create connectAck Messasge
    connectAckMsg = MESSAGE_Alloc(node,
        ADAPTATION_LAYER,
        ATM_PROTOCOL_SAAL,
        MSG_ATM_ADAPTATION_SaalPacket);

    MESSAGE_PacketAlloc(node,
        connectAckMsg,
        sizeof(SaalConnectAckPacket),
        TRACE_SAAL);

    connectAckPacket = (SaalConnectAckPacket*)
        MESSAGE_ReturnPacket(connectAckMsg);

    // NextHop & outgoing Interface for the nearest network element
    outIntf = interfaceIndex;
    memcpy(&nextHop, prevHop, sizeof(AtmAddress));

    //Fill in the Connect ack packet related IE
    // Common Part

    SaalFillCommonIEPart(node, SAAL_IE_CONNC_ID,
        &(connectAckPacket->conncId),
        sizeof(SaalIEConncIdentifier));

    // Specific part
    connectAckPacket->conncId.VCI = saalAppData->VCI;
    connectAckPacket->conncId.VPI = saalAppData->VPI;

    ieLength = connectAckPacket->conncId.ieField.IE_contentLn +
        sizeof(SaalInformationElement);

    // Fill in the header fields for the ConnectAckMsg
    SaalCreateCommonHeader(node,
        &connectAckPacket->header, SAAL_CONNECT_ACK, ieLength);

    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, connectAckMsg),
        &(atmIntf[outIntf].atmIntfAddr),
        prevHop,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_CONNECT_ACK);

    MESSAGE_Free(node, connectAckMsg);
    saalNodeData->stats.NumOfAtmConnectAckSent++;
}


// /**
// FUNCTION    :: SaalCallingUserReceiveReleaseComplMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CallingUser Process ReleaseComplMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCallingUserReceiveReleaseComplMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    //stop Timer T306
    SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T306);

    // change state to NULL
    saalAppData->state = SAAL_NULL;

    // Update the status for this VCI-VPI entry
    Aal5UpdateConncTable(node, saalAppData->VCI,
        saalAppData->VPI, SAAL_TERMINATED);

    SaalFreeNetworkResources(node, saalAppData);
}


// /**
// FUNCTION    :: SaalCalledNetworkReceiveReleaseComplMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Called Network Process ReleaseComplMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCalledNetworkReceiveReleaseComplMessage(Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    // stop Timer T306
    SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T306);

    // change state to NULL
    saalAppData->state = SAAL_NULL;
    SaalFreeNetworkResources(node, saalAppData);
}

// /**
// FUNCTION    :: SaalCommonNetworkReceiveReleaseComplMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Called Network Process ReleaseComplMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCommonNetworkReceiveReleaseComplMessage(Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    // stop Timer T306
    SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T306);

    // change state to NULL
    saalAppData->state = SAAL_NULL;
    SaalFreeNetworkResources(node, saalAppData);
}


// /**
// FUNCTION    :: SaalCalledNetworkReceiveReleaseMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CalledNetwork Process Release Message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCalledNetworkReceiveReleaseMessage(Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    int outIntf;
    AtmAddress nextHop ;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // start Timer T306
    SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
        saalAppData, saalAppData->outIntf, SAAL_TIMER_T306);

    // Fire the Timer
    timerData->timerPtr =
        SaalStartTimer(node, timerData,
        SAAL_TIMER_T306_DELAY,
        MSG_ATM_ADAPTATION_SaalT306Timer);

    // set signalling state to Release Indication
    saalAppData->state = SAAL_RELEASE_INDICATION;

    // Forwards the release message towars the called user

    // NextHop & outgoing Interface for the nearest network element
    outIntf = saalAppData->outIntf;
    memcpy(&nextHop, saalAppData->nextHopAddr, sizeof(AtmAddress));

    // Forward this packet towards destination
    AalSendSignalingMsgToLinkLayer (
        node,
        MESSAGE_Duplicate(node, msg),
        &(atmIntf[outIntf].atmIntfAddr),
        saalAppData->calledPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_RELEASE);

    saalNodeData->stats.NumOfAtmReleaseSent++;
}


// /**
// FUNCTION    :: SaalCommonNetworkReceiveReleaseMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Common network element Process Release Message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCommonNetworkReceiveReleaseMessage(Node* node,
    Message *msg, SaalAppData* saalAppData)
{
    int outIntf;
    AtmAddress nextHop ;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // start Timer T306
   SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
        saalAppData, saalAppData->outIntf, SAAL_TIMER_T306);

    // Fire the Timer
    timerData->timerPtr =
        SaalStartTimer(node, timerData,
        SAAL_TIMER_T306_DELAY,
        MSG_ATM_ADAPTATION_SaalT306Timer);

    // Create & send a release complete message
    // towards the calling user

    SaalSendReleaseCompleteMessage(node, saalAppData);

    // Forwards the release message towars the called user
    // NextHop & outgoing Interface for the nearest network element
    outIntf = saalAppData->outIntf;
    memcpy(&nextHop, saalAppData->nextHopAddr, sizeof(AtmAddress));

    // Forward this packet towards destination
    AalSendSignalingMsgToLinkLayer (
        node,
        MESSAGE_Duplicate(node, msg),
        &(atmIntf[outIntf].atmIntfAddr),
        saalAppData->calledPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_RELEASE);

    saalNodeData->stats.NumOfAtmReleaseSent++;
}


// /**
// FUNCTION    :: SaalCalledUserReceiveReleaseMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CalledUser Process ReleaseMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCalledUserReceiveReleaseMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    // set signalling state to Release Indication
    saalAppData->state = SAAL_RELEASE_INDICATION;

    // Create & send a release complete message
    // towards the calling user

    SaalSendReleaseCompleteMessage(node, saalAppData);

    // changes state to NULL
    saalAppData->state = SAAL_NULL;

    // free the resource reserved for this connection
    SaalFreeNetworkResources(node, saalAppData);
}


// /**
// FUNCTION    :: SaalCallingNetworkReceiveReleaseMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CallingNetwork Process ReleaseMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCallingNetworkReceiveReleaseMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    int outIntf;
    AtmAddress nextHop ;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // set signalling state to Release Request
    saalAppData->state = SAAL_RELEASE_REQUEST;

    // Create & send a release complete message
    // towards the calling user

    SaalSendReleaseCompleteMessage(node, saalAppData);

    // Forwards the release message towars the called user
    // NextHop & outgoing Interface for the nearest network element
    outIntf = saalAppData->outIntf;
    memcpy(&nextHop, saalAppData->nextHopAddr, sizeof(AtmAddress));

    // Forward this packet towards destination
    AalSendSignalingMsgToLinkLayer (
        node,
        MESSAGE_Duplicate(node, msg),
        &(atmIntf[outIntf].atmIntfAddr),
        saalAppData->calledPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_RELEASE);

    saalNodeData->stats.NumOfAtmReleaseSent++;

    // changes state to NULL
    saalAppData->state = SAAL_NULL;

    // free the resource reserved for this connection
    SaalFreeNetworkResources(node, saalAppData);
}


// /**
// FUNCTION    :: SaalCallingNetworkReceiveSetupMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CallingNetworkProcess SetupMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCallingNetworkReceiveSetupMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    BOOL supportVal = FALSE;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    // Checks if it supports all the IE parameters of setup
    // such as AAL, QoS, Bandwidth & other such parameters

    supportVal = SaalCheckForSupportOfIE(node, msg, saalAppData);

    if (!supportVal)
    {
        // the call is not supported so send
        // release complete to Calling user

        SaalSendReleaseCompleteMessage(node, saalAppData);
        return;
    }

    // set signalling state to Call initiated
    saalAppData->state = SAAL_CALL_INITIATED;

    // Now forward the setup message to the next Hop
    SaalForwardingSetupMessage(node, msg, saalAppData);

    // Create & send CallProceeding Messasge to the CALING_USER
    SaalSendCallProceedingMessage(node, saalAppData);

    // set signalling state to Outgoing Call-Proceeding
    saalAppData->state = SAAL_OUTGOING_CALL_PROCEEDING;
}


// /**
// FUNCTION    :: SaalCommonNetworkReceiveSetupMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Common network element Process SetupMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCommonNetworkReceiveSetupMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    BOOL supportVal = FALSE;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    // Checks if it supports all the IE parameters of setup
    // such as AAL, QoS, Bandwidth & other such parameters

    supportVal = SaalCheckForSupportOfIE(node, msg, saalAppData);

    if (!supportVal)
    {
        // the call is not supported so send
        // release complete to Calling user

        SaalSendReleaseCompleteMessage(node, saalAppData);
        return;
    }

    // set signalling state to Call initiated
    saalAppData->state = SAAL_CALL_INITIATED;

    // start Timer T303
    SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
                                    saalAppData,
                                    saalAppData->outIntf,
                                    SAAL_TIMER_T303);

    // Fire the Timer
    timerData->timerPtr =
        SaalStartTimer(node, timerData,
         SAAL_TIMER_T303_DELAY,
         MSG_ATM_ADAPTATION_SaalT303Timer);

    // Now forward the setup message to the next Hop
    SaalForwardingSetupMessage(node, msg, saalAppData);

    // Create & send CallProceeding Messasge to the
    // CALING_USER
    SaalSendCallProceedingMessage(node, saalAppData);

    // set signalling state to Outgoing Call-Proceeding
    saalAppData->state = SAAL_OUTGOING_CALL_PROCEEDING;

}


// /**
// FUNCTION    :: SaalCalledNetworkReceiveSetupMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CalledNetwork Process SetupMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCalledNetworkReceiveSetupMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    // start timer T303
    SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
        saalAppData, saalAppData->outIntf, SAAL_TIMER_T303);

    // Fire the Timer
    timerData->timerPtr =
        SaalStartTimer(node, timerData,
        SAAL_TIMER_T303_DELAY,
        MSG_ATM_ADAPTATION_SaalT303Timer);

    // change state to call present
    saalAppData->state = SAAL_CALL_PRESENT;

    // Now forward the setup message to the next Hop
    SaalForwardingSetupMessage(node, msg, saalAppData);
}


// /**
// FUNCTION    :: Aal5ChecksValidityFromUpperLayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Checking if the final destination is
//                available through this gateway
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : BOOL : TRUE | FALSE
// **/
BOOL Aal5ChecksValidityFromUpperLayer(
    Node* node,
    SaalAppData*saalAppData)
{
    int i;
    NodeAddress nextIp;
    int outgoingInterface;
    BOOL routeAvailable = FALSE;

    Aal5Data*   aal5Data =  AalGetPtrForThisAtmNode(node);
    Aal5InterfaceData* atmIntf =  aal5Data->myIntfData;

    // Check if I am exit point for this packet
    if (saalAppData->calledPartyNum->AFI != 0)
    {
        // check packet is for me
        for (i = 0; i < node->numAtmInterfaces; i++)
        {
            if ((saalAppData->calledPartyNum->ESI_pt1
                == atmIntf[i].atmIntfAddr.ESI_pt1)
                &&(saalAppData->calledPartyNum->ESI_pt2
                == atmIntf[i].atmIntfAddr.ESI_pt2))
            {
                routeAvailable = TRUE;
                return routeAvailable;
            }
        }
    }
    // If exit point not mentioned
    else
    {
        // search network forwarding table for
        // matching entry

        Atm_RouteThePacketUsingLookupTable(node,
            saalAppData->calledPartyAddr.interfaceAddr.ipv4,
            &outgoingInterface,
            &nextIp);

        if ((int)nextIp != NETWORK_UNREACHABLE)
        {
            routeAvailable = TRUE;

            // Modify SaalAppData

            // Update called party Num
            memcpy(saalAppData->calledPartyNum,
                &aal5Data->myIntfData[saalAppData->inIntf]. atmIntfAddr,
                sizeof(AtmAddress));

            // Update Address info table
            Aal5UpdateAddressInfoTable(node,
                DEFAULT_INTERFACE,
                saalAppData->calledPartyNum,
                &saalAppData->calledPartyAddr);

            return routeAvailable;
        }

        // For the case of true ATM Node
        // check for it's logical IP Addresses
        const LogicalSubnet* myLogicalSubnet =
            AtmGetLogicalSubnetFromNodeId(
            node,
            node->nodeId,
            DEFAULT_INTERFACE);

        if (myLogicalSubnet->ipAddress ==
            saalAppData->calledPartyAddr.interfaceAddr.ipv4)
        {
            routeAvailable = TRUE;

            // Modify SaalAppData

            // Update called party Num
            memcpy(saalAppData->calledPartyNum,
                &aal5Data->myIntfData[saalAppData->inIntf]. atmIntfAddr,
                sizeof(AtmAddress));

            // Update Address info table
            Aal5UpdateAddressInfoTable(node,
                DEFAULT_INTERFACE,
                saalAppData->calledPartyNum,
                &saalAppData->calledPartyAddr);

            return routeAvailable;
        }
    }

    return routeAvailable;

}


// /**
// FUNCTION    :: SaalCalledUserReceiveSetupMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CalledUser Process SetupMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCalledUserReceiveSetupMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;
    BOOL supportVal = FALSE;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    // change state to call present
    saalAppData->state = SAAL_CALL_PRESENT;

    // send callProceeding towards the N-UNI of Called_NET_SWITCH
    // Create & send CallProceeding Messasge to the
    SaalSendCallProceedingMessage(node,  saalAppData);

    // change state to incoming call proceeding
    saalAppData->state = SAAL_INCOMING_CALL_PROCEEDING;

    // After sending Call-Proceeding end User checks if
    // it supports all the IE parameters of set up , such as
    // AAL, QoS, Bandwidth & other such parameters

    supportVal = SaalCheckForSupportOfIE(node, msg, saalAppData);

    if (!supportVal)
    {
        // the call is not supported so send
        // release complete to prevHop

        SaalSendReleaseCompleteMessage(node, saalAppData);
        return;
    }

    // check if route to final dest is available thru this node
    // If final destination is available send alert message
    // so a timer is fired for
    // Adaptation layer to send Allert message
    // Create & send an ALERT message towards the source

    if (Aal5ChecksValidityFromUpperLayer(node, saalAppData))
    {
        // Modify my saal App List

        // It is a valid gateway for reaching destination
        SaalSendAlertingMessage(node, saalAppData);

        // change state to CallReceived
        saalAppData->state = SAAL_CALL_RECEIVED;

        // After sending Alert end User waits for some time
        // (e.g. time to pick up the phone) then it sends a connect msg
        // In simulation, a delay Timer SAAL_CONNECT_TIMER is introduced

        // Start Timer for Connect
        SaalTimerData*  timerData;

        // Search for matching entry from Timer List
        timerData = SaalUpdateTimerList(node,
            saalAppData, saalAppData->inIntf, SAAL_TIMER_CONNECT);

        // Fire the Timer
        timerData->timerPtr = SaalStartTimer(node, timerData,
            SAAL_CONNECT_TIMER_DELAY,
            MSG_ATM_ADAPTATION_SaalConnectTimer);
    }
    else
    {
        if (DEBUG)
        {
            printf(" Node %u: route for %d not avl thru this node\n",
                node->nodeId, saalAppData->VCI);
        }

        // free the resource reserved for this connection
        SaalFreeNetworkResources(node, saalAppData);

    }
}


// /**
// FUNCTION    :: SaalCalledNetworkReceiveConnectMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CalledNetwork process ConnectMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// + prevHop    : AtmAddress* : Pointer to previous hop.
// + interfaceIndex : int : Interface index.
// RETURN       : void : None
// **/
void SaalCalledNetworkReceiveConnectMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData,
    AtmAddress* prevHop,
    int interfaceIndex)
{
    int outIntf;
    AtmAddress nextHop;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // stop Timer T301
    SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T301);

    // change state to Connect Request
    saalAppData->state = SAAL_CONNECT_REQUEST;

    // Create & send CONNECT ACK mesasge towards the called user
    SaalSendConnectAcknowledgeMessage(node,
        prevHop, interfaceIndex, saalAppData);

    // changes its state to Active
    saalAppData->state = SAAL_ACTIVE;

    if (DEBUG)
    {
        printf(" #%u (I am %d) is ready for data transfer \n",
            node->nodeId, saalAppData->endPointType);
        SaalPrintAppList(node);
    }

    //NextHop & outgoing Interface for the nearest network element
    // Forward the connect packet towards the source
    outIntf = saalAppData->inIntf;
    memcpy(&nextHop, saalAppData->prevHopAddr, sizeof(AtmAddress));

    // forwards connect message towards the calling user
    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, msg),
        saalAppData->calledPartyNum,
        saalAppData->callingPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_CONNECT);

    saalNodeData->stats.NumOfAtmConnectSent++;
}


// /**
// FUNCTION    :: SaalCommonNetworkReceiveConnectMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Common network element process ConnectMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// + prevHop    : AtmAddress* : Pointer to previous hop.
// + interfaceIndex : int : Interface index.
// RETURN       : void : None
// **/
void SaalCommonNetworkReceiveConnectMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData,
    AtmAddress* prevHop,
    int interfaceIndex)
{
    int outIntf;
    AtmAddress nextHop;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // stop Timer T301
    SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T301);

    // Create & send CONNECT ACK mesasge towards the called user
    SaalSendConnectAcknowledgeMessage(node,
        prevHop, interfaceIndex, saalAppData);

    // changes its state to Active
    saalAppData->state = SAAL_ACTIVE;

    if (DEBUG)
    {
        printf(" #%u (I am %d) is ready for data transfer \n",
            node->nodeId, saalAppData->endPointType);
        SaalPrintAppList(node);
    }

    //NextHop & outgoing Interface for the nearest network element
    // Forward the connect packet towards the source

    outIntf = saalAppData->inIntf;
    memcpy(&nextHop, saalAppData->prevHopAddr, sizeof(AtmAddress));

    // forwards connect message towards the calling user
    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, msg),
        saalAppData->calledPartyNum,
        saalAppData->callingPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_CONNECT);

    saalNodeData->stats.NumOfAtmConnectSent++;
}


// /**
// FUNCTION    :: SaalCallingNetworkReceiveConnectMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CallingNetwork Process ConnectMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCallingNetworkReceiveConnectMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    int outIntf;
    AtmAddress nextHop ;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // NextHop & outgoing Interface for the nearest network element
    // Forward the connect packet towards the source

    outIntf = saalAppData->inIntf;
    memcpy(&nextHop, saalAppData->prevHopAddr, sizeof(AtmAddress));

    // send it towards the calling User
    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, msg),
        saalAppData->calledPartyNum,
        saalAppData->callingPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_CONNECT);

    saalNodeData->stats.NumOfAtmConnectSent++;

    // change state to active state
    saalAppData->state = SAAL_ACTIVE;

    if (DEBUG)
    {
        printf(" #%u (I am %d) is ready for data transfer \n",
            node->nodeId, saalAppData->endPointType);
        SaalPrintAppList(node);
    }
}


// /**
// FUNCTION    :: SaalCallingUserReceiveConnectMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CallingUser Process ConnectMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCallingUserReceiveConnectMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    // change state to Active
    saalAppData->state = SAAL_ACTIVE;

    // stop Timer T301
    SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T301);

    // The connection between the calling used & called user
    // is now ready for data Transfer
    if (DEBUG)
    {
        printf(" #%u (I am %d) is ready for data transfer \n",
            node->nodeId, saalAppData->endPointType);
        SaalPrintAppList(node);
    }
}


// /**
// FUNCTION    :: SaalCalledUserReceiveConnectAckMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CalledUser Process ConnectAckMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCalledUserReceiveConnectAckMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    // stop Timer T313
    SaalStopsTimer(node, saalAppData,
        saalAppData->inIntf, SAAL_TIMER_T313);

    // change its state to Active
    saalAppData->state = SAAL_ACTIVE;

    if (DEBUG)
    {
        printf(" #%u (I am %d) is ready for data transfer \n",
            node->nodeId, saalAppData->endPointType);
        SaalPrintAppList(node);
    }
}


// /**
// FUNCTION    :: SaalCalledNetworkReceiveAlertMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CalledNetwork process AlertMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCalledNetworkReceiveAlertMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    int outIntf;
    AtmAddress nextHop ;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    //stops Timer T310
    SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T310);

    // start Timer T301
    SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
        saalAppData, saalAppData->outIntf, SAAL_TIMER_T301);

    // Fire the Timer
    timerData->timerPtr = SaalStartTimer(node, timerData,
        SAAL_TIMER_T301_DELAY,
        MSG_ATM_ADAPTATION_SaalT301Timer);

    // Change state to CALL_RECEIVED
    saalAppData->state = SAAL_CALL_RECEIVED;

    // Forward the Alert packet towards the source
    outIntf = saalAppData->inIntf;
    memcpy(&nextHop, saalAppData->prevHopAddr,
    sizeof(AtmAddress));

    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, msg),
        saalAppData->calledPartyNum,
        saalAppData->callingPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_ALERT);

    saalNodeData->stats.NumOfAtmAlertSent++;
}


// /**
// FUNCTION    :: SaalCommonNetworkReceiveAlertMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Common network element process AlertMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCommonNetworkReceiveAlertMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    int outIntf;
    AtmAddress nextHop ;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;


    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    //stops Timer T310
    SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T310);

    // start Timer T301
    SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
        saalAppData, saalAppData->outIntf, SAAL_TIMER_T301);

    // Fire the Timer
    timerData->timerPtr =
        SaalStartTimer(node, timerData,
        SAAL_TIMER_T301_DELAY,
        MSG_ATM_ADAPTATION_SaalT301Timer);

    // Change state to CALL_RECEIVED
    saalAppData->state = SAAL_CALL_RECEIVED;

    // Forward the Alert packet towards the source
    outIntf = saalAppData->inIntf;
    memcpy(&nextHop, saalAppData->prevHopAddr, sizeof(AtmAddress));

    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, msg),
        saalAppData->calledPartyNum,
        saalAppData->callingPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_ALERT);

    saalNodeData->stats.NumOfAtmAlertSent++;
}


// /**
// FUNCTION    :: SaalCallingNetworkReceiveAlertMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: CallingNetwork Process AlertMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCallingNetworkReceiveAlertMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    int outIntf;
    AtmAddress nextHop ;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    //stops Timer T310
    SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T310);

    // Forward the Alert packet towards the source
    outIntf = saalAppData->inIntf;
    memcpy(&nextHop, saalAppData->prevHopAddr, sizeof(AtmAddress));

    AalSendSignalingMsgToLinkLayer(
        node,
        MESSAGE_Duplicate(node, msg),
        saalAppData->calledPartyNum,
        saalAppData->callingPartyNum,
        AAL_SAAL_TTL,
        outIntf,
        &nextHop,
        SAAL_ALERT);

    saalNodeData->stats.NumOfAtmAlertSent++;

    // Change state to CALL_RECEIVED
    saalAppData->state = SAAL_CALL_RECEIVED;
}


// /**
// FUNCTION    :: SaalCallingUserReceiveAlertMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Calling user receieve Alert message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCallingUserReceiveAlertMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    Aal5Data* aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    // stop timer T310
     SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T310);

    // start Timer T301
    SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
        saalAppData, saalAppData->outIntf, SAAL_TIMER_T301);

    // Fire the Timer
    timerData->timerPtr = SaalStartTimer(node, timerData,
        SAAL_TIMER_T301_DELAY,
        MSG_ATM_ADAPTATION_SaalT301Timer);

    // Change state to CALL_DELIVERED
    saalAppData->state = SAAL_CALL_DELIVERED;
}


// /**
// FUNCTION    :: SaalCallingUserReceiveCallProcMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Calling User receieve call proceeding Message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCallingUserReceiveCallProcMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{


    // stop timer T303
     SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T303);

    // change state
    saalAppData->state = SAAL_OUTGOING_CALL_PROCEEDING;

    // start Timer T310

    SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
        saalAppData, saalAppData->outIntf, SAAL_TIMER_T310);

    // Fire the Timer
    timerData->timerPtr = SaalStartTimer(node, timerData,
        SAAL_TIMER_T310_DELAY,
        MSG_ATM_ADAPTATION_SaalT310Timer);
}


// /**
// FUNCTION    :: SaalCalledNetworkReceiveCallProcMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Called Network Receive Call Proceeding message
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCalledNetworkReceiveCallProcMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    // stop timer T303
     SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T303);

    // start Timer T310
    SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
        saalAppData, saalAppData->outIntf, SAAL_TIMER_T310);

    // Fire the Timer
    timerData->timerPtr = SaalStartTimer(node,
        timerData,
        SAAL_TIMER_T310_DELAY,
        MSG_ATM_ADAPTATION_SaalT310Timer);

    // change state to Incoming call proceeding
    saalAppData->state = SAAL_INCOMING_CALL_PROCEEDING;
}


// /**
// FUNCTION    :: SaalCommonNetworkReceiveCallProcMessage
// LAYER       :: Adaptation Layer
// PURPOSE     :: Common Network element ReceiveCallProcMessage
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalCommonNetworkReceiveCallProcMessage(
    Node* node,
    Message *msg,
    SaalAppData* saalAppData)
{
    // stop timer T303
     SaalStopsTimer(node, saalAppData,
        saalAppData->outIntf, SAAL_TIMER_T303);

    // start Timer T310
    SaalTimerData*  timerData;

    // Search for matching entry from Timer List
    timerData = SaalUpdateTimerList(node,
        saalAppData, saalAppData->outIntf, SAAL_TIMER_T310);

    // Fire the Timer
    timerData->timerPtr = SaalStartTimer(node, timerData,
        SAAL_TIMER_T310_DELAY,
        MSG_ATM_ADAPTATION_SaalT310Timer);
}


// /**
// FUNCTION    :: SaalRefreshConnectionTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Connection table is refreshed here
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// RETURN       : void : None
// **/
void SaalRefreshConnectionTable(Node* node, Message* msg)
{
    Aal5Data*   aal5Data = AalGetPtrForThisAtmNode(node);

    SaalTimerData* timerInfo =
        (SaalTimerData*) MESSAGE_ReturnInfo(msg);

    SaalAppData* saalAppData = NULL;
    Aal5ConncTable* conncTable = &aal5Data->conncTable;
    Aal5ConncTableRow* row;
    unsigned int i;

    //search for matching entry in connc table

    for (i = 0; i < conncTable->numRows; i++)
    {
        row = &conncTable->row[i];

        if (row->VCI == timerInfo->VCI)
        {
            // Matching Entry available

            // check the tiem free which the conncetion id free,
            // i.e no data during thart time

            if (DEBUG)
            {
                char clockStr[MAX_STRING_LENGTH];

                ctoa(node->getNodeTime(), clockStr);
                printf(" Connection %d current time %s \n",
                    row->VCI, clockStr);

                ctoa(row->lastPktRecvdTime, clockStr);
                printf(" Connection %d lastpktRecvd %s time \n",
                    row->VCI, clockStr);

                ctoa(node->getNodeTime()- row->lastPktRecvdTime, clockStr);
                printf(" IDLE time %s \n", clockStr);
            }

            // get the associated Saal App Data
            saalAppData =
                SaalGetDataForThisApp(node, row->VCI, row->VPI);

            if (saalAppData)
            {
                // if the time is more than connection timeout
                // time. Release the resources reserved for it

                if (node->getNodeTime()- row->lastPktRecvdTime
                    >= aal5Data->myIntfData[saalAppData
                    ->outIntf].conncTimeoutTime)
                {
                    if (DEBUG)
                    {
                        printf(" Node %u: TimeOut for VCI %d \n",
                            node->nodeId, row->VCI);
                    }
                    SaalTerminateConnection(node, saalAppData);
                }

                else
                {
                    if (DEBUG)
                    {
                        printf("Node %u: Refresh table for VCI %d seq %d\n",
                            node->nodeId, row->VCI, timerInfo->seqNo + 1);
                    }

                    // RESET the Timer
                    SaalTimerData* newTimerInfo;
                    Message* timeoutMsg;

                    timeoutMsg = MESSAGE_Duplicate (node, msg);
                    newTimerInfo =
                        (SaalTimerData*) MESSAGE_ReturnInfo(timeoutMsg);

                    newTimerInfo->seqNo = timerInfo->seqNo + 1 ;
                    newTimerInfo->VCI = row->VCI;
                    newTimerInfo->VPI = row->VPI;

                    MESSAGE_Send(node, (Message*)timeoutMsg,
                        aal5Data->myIntfData[saalAppData
                        ->outIntf].conncRefreshTime);
                }
            }   // if valid saal App data available
            return;
        }   // if matching entry exist
    }   // end of for
}


// /**
// FUNCTION    :: SaalUserUpdateVariousTables
// LAYER       :: Adaptation Layer
// PURPOSE     :: Update entry in various table
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + saalAppData : SaalAppData* : Pointer to SAAL app data.
// RETURN       : void : None
// **/
void SaalUserUpdateVariousTables(Node* node,
                                 SaalAppData* saalAppData)
{
    Address nextHopAddr;

    // This node has reached to Active state
    // So it is ready for data transfer
    // And build an entry in the Translation table

    SaalUpdateTransTable(node, saalAppData, saalAppData->outIntf);

    // Update Fwding table
    // Get NextHop ATM switch Addr

    nextHopAddr = Atm_GetAddrForOppositeNodeId(node,
        saalAppData->outIntf);

    memcpy(saalAppData->nextHopAddr,
        &nextHopAddr.interfaceAddr.atm,
        sizeof(AtmAddress));

    Aal5UpdateFwdTable(node,
        saalAppData->outIntf,
        saalAppData->calledPartyNum,
        saalAppData->nextHopAddr);

    if (saalAppData->endPointType == CALLING_USER)
    {
        // Update connection table
        Aal5UpdateConncTable(node, saalAppData->VCI,
            saalAppData->VPI, SAAL_COMPLETED);

        // Update Address info table
        Aal5UpdateAddressInfoTable(node,
            DEFAULT_INTERFACE,
            saalAppData->calledPartyNum,
            &saalAppData->calledPartyAddr);
    }
}


// /**
// FUNCTION    :: AtmSAALInit
// LAYER       :: Adaptation Layer
// PURPOSE     :: Innitialization of SAAL in ATM
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + saalLayerPtr : SaalNodeData** : SAAL layer pointer.
// + nodeInput  : const NodeInput * : Pointer to config file.
// RETURN       : void : None
// **/
void AtmSAALInit(
    Node *node,
    SaalNodeData** saalLayerPtr,
    const NodeInput *nodeInput)
{
    BOOL retVal;
    char buf[100];
    int i;

    // initialize signaling parameter
    Aal5Data*   aal5Data;
    Aal5InterfaceData* atmIntf;

    SaalNodeData* saalNodeData =
        (SaalNodeData*) MEM_malloc (sizeof(SaalNodeData));

    memset(saalNodeData, 0, sizeof(SaalNodeData));

    saalNodeData->saalIntf = (SaalInterfaceData*)
        MEM_malloc(sizeof(SaalInterfaceData)
        * (node->numAtmInterfaces));

    memset(saalNodeData->saalIntf,
        0,
        sizeof(SaalInterfaceData) * (node->numAtmInterfaces));

    // Set AAL5 related parameter
    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    *saalLayerPtr = saalNodeData;

    // Init aal5Data SaalStatistics
    memset(&saalNodeData->stats, 0, sizeof(SaalStats));

    // Init a list for storing application specific info
    ListInit(node, &saalNodeData->appList);

    // Set Virtual path in each link
    for (i = 0; i < node->numAtmInterfaces; i++)
    {
        // various Virtual Path having specified BW
        // exist within the given link bandwidth

        // Presently it is assumed each VPI has BW 0.5 Mbps
        // Accordingly set the number of maximum VPI that
        // can exist for that interface

        saalNodeData->saalIntf[i].maxVPI =
            atmIntf[i].totalBandwidth / SAAL_DEFAULT_BW;

        // numVPI indicates how many VPI are used;
        // during initialization it is 0
        // ach application passing through this
        // interface reserve one VPI
        saalNodeData->saalIntf[i].numVPI = 0;

        // Init a list for storing related
        // parameters for each application
        ListInit(node, &saalNodeData->saalIntf[i].vpiList);
    }

    // Determine whether or not to print the stats
    IO_ReadString(node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ATM-SIGNALLING-STATISTICS",
        &retVal,
        buf);

    if ((retVal == FALSE) || (strcmp (buf, "NO") == 0))
    {
        saalNodeData->printSaalStat = FALSE;
    }
    else if (strcmp (buf, "YES") == 0)
    {
        saalNodeData->printSaalStat = TRUE;
    }
}


// /**
// FUNCTION    :: SaalStartSignalingProcess
// LAYER       :: Adaptation Layer
// PURPOSE     :: To start signaling process.
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : Virtual connection identifire.
// + VPI        : unsigned char :  VPI value for SAAL.
// + srcAddr    : Address : Source address.
// + destAddr   : Address : Destination address.
// RETURN       : void : None
// **/
void SaalStartSignalingProcess(
    Node* node,
    unsigned short VCI,
    unsigned char VPI,
    Address srcAddr,
    Address destAddr)
{
    AtmAddress destAtmAddr;
    AtmAddress thisIntfAddr;

    SaalAppData* saalAppData = NULL;

    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);

    if (DEBUG)
    {
        printf(" %u start SAAL with VCI %d & VPI %d \n",
            node->nodeId, VCI, VPI);
    }

    // Get the responsible exit point and its
    // associated Atm Addr form Address Info Table

    Aal5GetAtmAddrAndLogicalIPForDest(
        node,
        destAddr,
        &destAtmAddr);

    // This intf addr is acting as the entry point
    // for this packet
    memcpy(&thisIntfAddr,
       &aal5Data->myIntfData[DEFAULT_INTERFACE].atmIntfAddr,
            sizeof(AtmAddress));

    // New application so create a new entry in appList
    // Create a new entry in Fwd table

    SaalSetNewSession(node,
        srcAddr,
        destAddr,
        &thisIntfAddr,
        &destAtmAddr,
        &thisIntfAddr,
        SAAL_INVALID_INTERFACE,
        VCI,
        VPI);

    saalAppData = SaalGetDataForThisApp(node, VCI, VPI);

    // Update the status for this VCI-VPI entry
    Aal5UpdateConncTable(node, VCI, VPI, SAAL_IN_PROGRESS);

    SaalSendSetupMessage(node, saalAppData);

    // set signalling state to Call-Initiated
    saalAppData->state = SAAL_CALL_INITIATED;
}



// /**
// FUNCTION    :: SaalHandleProtocolEvent
// LAYER       :: Adaptation Layer
// PURPOSE     :: Protocol event handelling function for SAAL.
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : None
// **/
void SaalHandleProtocolEvent(Node* node, Message* msg)
{
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;
    SaalAppData* saalAppData = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;

    switch (msg->eventType)
    {
    case MSG_ATM_ADAPTATION_SaalTimeoutTimer:
        {
            // Check the connection table status
            // and if it is timeout release the reserved resources
            // otherwise refresh the connection table

            SaalRefreshConnectionTable(node, msg);
            break;
        }

    case MSG_ATM_ADAPTATION_SaalConnectTimer:
        {
            // After sending Alert end User waits for some time
            // (e.g. time to pick up the phone)

            SaalTimerData* info =
                (SaalTimerData*)MESSAGE_ReturnInfo(msg);

            saalAppData = SaalGetDataForThisApp(node,
                info->VCI, info->VPI);

            if (!saalAppData)
            {
                break;
            }

            // Create & send Connect Message towards the Calling party
            SaalSendConnectMessage(node, saalAppData);

            // start Timer T313
            SaalTimerData*  timerData;

            // Search for matching entry from Timer List
            timerData = SaalUpdateTimerList(node,
                saalAppData, saalAppData->inIntf, SAAL_TIMER_T313);

            // Fire the Timer
            timerData->timerPtr = SaalStartTimer(node, timerData,
                SAAL_TIMER_T313_DELAY,
                MSG_ATM_ADAPTATION_SaalT313Timer);

            // change state to Connect Request
            saalAppData->state = SAAL_CONNECT_REQUEST;

            break;
        }
    case MSG_ATM_ADAPTATION_SaalT301Timer:
        {
            // starts when alert received
            // and stops when Connect received

            SaalTimerData* info =
                (SaalTimerData*)MESSAGE_ReturnInfo(msg);

            saalAppData = SaalGetDataForThisApp(node,
                info->VCI, info->VPI);

            if (!saalAppData)
            {
                break;
            }

            // clear the call on first expiry
            if (info->seqNo == 1)
            {
                SaalTerminateConnection(node, saalAppData);
            }
            break;
        }
    case MSG_ATM_ADAPTATION_SaalT303Timer:
        {
            // starts when Setup Sent and
            // stops when Alert/Connect/Release Compl/Call-Proc received

            SaalTimerData* info =
                (SaalTimerData*)MESSAGE_ReturnInfo(msg);

            saalAppData = SaalGetDataForThisApp(node,
                info->VCI, info->VPI);

            if (!saalAppData)
            {
                break;
            }

            if (DEBUG)
            {
                printf(" %u: T303: seq %d & intf %d \n",
                    node->nodeId, info->seqNo, info->intfId);
            }

            // If no response to the SETUP message is received
            // by the user before the first expiry of timer T303
            // resend setup & restart T303 on first expiry

            if (info->seqNo == 1)
            {
                int outIntf =  SAAL_INVALID_INTERFACE;
                AtmAddress nextHop;

                // Check for out intf &  nextHop to
                // final Destination

                if (saalAppData->calledPartyNum->AFI != 0)
                {
                    AalGetOutIntfAndNextHopForDest(node,
                        saalAppData->calledPartyNum,
                        &outIntf,
                        &nextHop);
                }

                // If this is a route to final destination
                if (outIntf == info->intfId)
                {
                    // if I am the calling user resend setup
                    if (saalAppData->endPointType == CALLING_USER)
                    {
                        SaalSendSetupMessage(node, saalAppData);
                    }
                }
                else
                {
                    // no route available thru this intf
                    // so reset Virtual Path
                    SaalResetVirtualPath(node,
                        saalAppData, info->intfId);
                }
            }

            // clear network connection & enter NULL state on second expiry
            if (info->seqNo == 2)
            {
                SaalTerminateConnection(node, saalAppData);

                // free the resource reserved for this connection
                SaalFreeNetworkResources(node, saalAppData);
            }

            break;
        }
    case MSG_ATM_ADAPTATION_SaalT306Timer:
        {
            // starts when Release with progress ind received
            // and stops when Rel compl received

            SaalTimerData* info =
                (SaalTimerData*)MESSAGE_ReturnInfo(msg);

            saalAppData = SaalGetDataForThisApp(node,
                info->VCI, info->VPI);

            // If there is no entry for this application or
            // I am the source no need to send release complete

            if ((!saalAppData)
                || (saalAppData->inIntf == SAAL_INVALID_INTERFACE))
            {
                break;
            }

            // Send release Complete on first expiry

            if (info->seqNo == 1)
            {
                SaalSendReleaseCompleteMessage(node, saalAppData);
            }
            break;
        }
    case MSG_ATM_ADAPTATION_SaalT310Timer:
        {
            // starts when Call proceedings received
            // and stops when Alert/Connect/Release  received

            SaalTimerData* info =
                (SaalTimerData*)MESSAGE_ReturnInfo(msg);

            saalAppData = SaalGetDataForThisApp(node,
                info->VCI, info->VPI);

            if (!saalAppData)
            {
                break;
            }

            // clear the call on first expiry
            if (info->seqNo == 1)
            {
                // free the resources on that interface
                Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
                aal5Data->stats.numPktDroppedForNoRoute ++;

                SaalResetVirtualPath(node, saalAppData, info->intfId);

                // SaalTerminateConnection(node, saalAppData);
            }
            break;
        }

    case MSG_ATM_ADAPTATION_SaalT313Timer:
        {
            // starts when Connect sent
            // and stops when Connc. ack received

            SaalTimerData* info =
                (SaalTimerData*)MESSAGE_ReturnInfo(msg);

            saalAppData = SaalGetDataForThisApp(node,
                info->VCI, info->VPI);

            if (!saalAppData)
            {
                break;
            }

            // Send release on first expiry
            if (info->seqNo == 1)
            {
                SaalSendReleaseMessage(node, saalAppData);
            }
            break;
        }
    default:
        {
            char errStr[MAX_STRING_LENGTH];

            // Shouldn't get here.
            sprintf(errStr, "Node %u: Got invalid saal timer\n",
                node->nodeId);
            ERROR_Assert(FALSE, errStr);
        }
    }// end switch
    MESSAGE_Free(node, msg);
}


// /**
// FUNCTION    :: SaalHandleProtocolPacket
// LAYER       :: Adaptation Layer
// PURPOSE     :: Protocol packet handelling function for SAAL.
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// + interfaceIndex : int : interface index.
// RETURN       : void : None
// **/
void SaalHandleProtocolPacket(
    Node* node,
    Message* msg,
    int interfaceIndex)
{
    SaalMsgHeader* saalMsgHdr = NULL;
    Aal5Data*   aal5Data = NULL;
    Aal5InterfaceData* atmIntf = NULL;
    AtmAddress prevHop;
    unsigned short VCI;
    unsigned char VPI;

    Address prevHopAddr =
        Atm_GetAddrForOppositeNodeId(node, interfaceIndex);

    memcpy(&prevHop,
        &prevHopAddr.interfaceAddr.atm,
        sizeof(AtmAddress));

    SaalAppData* saalAppData = NULL;

    aal5Data = AalGetPtrForThisAtmNode(node);
    atmIntf = aal5Data->myIntfData;
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    // Get Saal header
    saalMsgHdr = (SaalMsgHeader*) MESSAGE_ReturnPacket(msg);

    // What type of packet did we get?
    switch (saalMsgHdr->messageType)
    {
        // It's a Setup packet.
    case SAAL_SETUP:
        {
            AtmAddress* sourceAtmAddr;
            AtmAddress* destAtmAddr;

            if (DEBUG)
            {
                printf(" #%u receiveSetup from %x intf %d\n",
                    node->nodeId, prevHop.ESI_pt1, interfaceIndex);
            }

            saalNodeData->stats.NumOfAtmSetupRecv++;

            // Get the setup packet.
            SaalSetupPacket* setupPkt =
                (SaalSetupPacket*)MESSAGE_ReturnPacket(msg);

            sourceAtmAddr =
                &(setupPkt->callingPartyNum.CallingPartyNum);
            destAtmAddr =
                &(setupPkt->calledPartyNum.CalledPartyNum);

            VCI = setupPkt->conncId.VCI;
            VPI = setupPkt->conncId.VPI;

            saalAppData = SaalGetDataForThisApp(node,
                VCI, VPI);

            if (!saalAppData)
            {
                // new application so need to build an entry

                SaalSetNewSession(node,
                  setupPkt->callingPartyAddr.callingPartyAddr,
                  setupPkt->calledPartyAddr.calledPartyAddr,
                  &(setupPkt->callingPartyNum.CallingPartyNum),
                  &(setupPkt->calledPartyNum.CalledPartyNum),
                  &prevHop,
                  interfaceIndex,
                  VCI,
                  VPI);

                saalAppData = SaalGetDataForThisApp(node,
                                    VCI, VPI);
            }
            else
            {
                // this setup is already processed
                MESSAGE_Free(node, msg);
                return;
            }

            // Otherwise Proceed

            // Check availbale Band Width
            BOOL supportVal = FALSE;

            // Checks if it supports all the IE parameters of setup
            // such as AAL, QoS, Bandwidth & other such parameters

            supportVal = SaalCheckForSupportOfIE(node, msg, saalAppData);

            if (!supportVal)
            {
                // the call is not supported so send
                // release complete to Calling user

                SaalSendReleaseCompleteMessage(node, saalAppData);

                MESSAGE_Free(node, msg);
                return;
            }

            if (saalAppData->endPointType == CALLING_NET_SWITCH)
            {
                SaalCallingNetworkReceiveSetupMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == CALLED_NET_SWITCH)
            {
                SaalCalledNetworkReceiveSetupMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == CALLED_USER)
            {
                SaalCalledUserReceiveSetupMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == COMMON_NET_SWITCH)
            {
                SaalCommonNetworkReceiveSetupMessage(node,
                    msg, saalAppData);
            }
            else
            {
                SaalForwardingSetupMessage(node, msg, saalAppData);
            }
            break;
        }
    case SAAL_CALL_PROCEEDING:
        {
            if (DEBUG)
            {
                printf(" #%u receive CallProceeding from %x \n",
                    node->nodeId, prevHop.ESI_pt1);
            }

            // Get the Call proceeding packet.
            SaalCallProcPacket* callProcPkt =
                (SaalCallProcPacket*)MESSAGE_ReturnPacket(msg);

            VCI = callProcPkt->conncId.VCI;
            VPI = callProcPkt->conncId.VPI;

            saalAppData = SaalGetDataForThisApp(node, VCI, VPI);

            if (!saalAppData)
            {
                break;
            }

            // Store he temporary value for outIntf
            saalAppData->outIntf = interfaceIndex;

            saalNodeData->stats.NumOfAtmCallProcRecv++;

            if (saalAppData->endPointType == CALLING_USER)
            {
                SaalCallingUserReceiveCallProcMessage(node,
                    msg, saalAppData);
            }
            else if ((saalAppData->endPointType == CALLED_NET_SWITCH)
                ||(saalAppData->endPointType == NORMAL_POINT))
            {
                SaalCalledNetworkReceiveCallProcMessage(node,
                    msg, saalAppData);
            }
            else if ((saalAppData->endPointType == CALLING_NET_SWITCH)
                ||(saalAppData->endPointType == COMMON_NET_SWITCH))
            {
                 // Thus it is common node present in between
                 // calling user & called user

                 SaalCommonNetworkReceiveCallProcMessage(node,
                                                         msg,
                                                         saalAppData);
            }
            else
            {
                char errStr[MAX_STRING_LENGTH];

                // Shouldn't get here.
                sprintf(errStr,
                    "#%u: EndPtType %d get wrong CallProc from %x\n",
                    node->nodeId, saalAppData->endPointType,
                    prevHop.ESI_pt1);
                ERROR_Assert(FALSE, errStr);
            }
            break;
        }
    case SAAL_ALERT:
        {
            if (DEBUG)
            {
                printf(" #%u receive Alert from %x\n",
                    node->nodeId, prevHop.ESI_pt1);
            }

            // Get the Alert packet
            SaalAlertPacket* alertPkt =
                (SaalAlertPacket*)MESSAGE_ReturnPacket(msg);

            VCI = alertPkt->conncId.VCI;
            VPI = alertPkt->conncId.VPI;

            saalAppData = SaalGetDataForThisApp(node, VCI, VPI);

            if (!saalAppData)
            {
                break;
            }

            // update Associated saalAppData
            saalAppData->outIntf = interfaceIndex ;

            if ((saalAppData->nextHopAddr->ESI_pt1 != 0) &&
                (saalAppData->nextHopAddr->ESI_pt1 !=
                prevHop.ESI_pt1))
            {
                // printf(" ALREADY UPDATED for this \n");

                MESSAGE_Free(node, msg);
                return;
            }

            memcpy(saalAppData->nextHopAddr,
                &prevHop,
                sizeof(AtmAddress));

            memcpy(saalAppData->calledPartyNum,
                &alertPkt->calledPartyNum.CalledPartyNum,
                sizeof(AtmAddress));

            // Update my endPoint Type
            SaalCheckEndPointType(node, saalAppData);

            saalNodeData->stats.NumOfAtmAlertRecv++;

            if (saalAppData->endPointType == CALLED_NET_SWITCH)
            {
                SaalCalledNetworkReceiveAlertMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == CALLING_NET_SWITCH)
            {
                SaalCallingNetworkReceiveAlertMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == CALLING_USER)
            {
                SaalCallingUserReceiveAlertMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == COMMON_NET_SWITCH)
            {
                SaalCommonNetworkReceiveAlertMessage(node,
                    msg, saalAppData);
            }
            else
            {
                // forward it towards the source
                int outIntf;
                AtmAddress nextHop;

                // It is a normal in-between switch point
                // Forward the Alert packet towards the source

                outIntf = saalAppData->inIntf;
                memcpy(&nextHop, saalAppData->prevHopAddr,
                    sizeof(AtmAddress));

                AalSendSignalingMsgToLinkLayer(
                    node,
                    MESSAGE_Duplicate(node, msg),
                    saalAppData->calledPartyNum,
                    saalAppData->callingPartyNum,
                    AAL_SAAL_TTL,
                    outIntf,
                    &nextHop,
                    SAAL_ALERT);

                saalNodeData->stats.NumOfAtmAlertSent++;
            }
            break;
        }
    case SAAL_CONNECT:
        {
            if (DEBUG)
            {
                printf(" #%u receive Connect from %x\n",
                    node->nodeId, prevHop.ESI_pt1);
            }
            // Get the Connect packet
            SaalConnectPacket* connectPkt =
                (SaalConnectPacket*)MESSAGE_ReturnPacket(msg);

            VCI = connectPkt->conncId.VCI;
            VPI = connectPkt->conncId.VPI;

            saalAppData = SaalGetDataForThisApp(node, VCI, VPI);

            if (!saalAppData)
            {
                break;
            }

            saalNodeData->stats.NumOfAtmConnectRecv++;

            // update Associated saalAppData
            saalAppData->outIntf = interfaceIndex;

            if (saalAppData->endPointType == CALLED_NET_SWITCH)
            {
                SaalCalledNetworkReceiveConnectMessage(node,
                    msg, saalAppData, &prevHop, interfaceIndex);
            }
            else if (saalAppData->endPointType == CALLING_NET_SWITCH)
            {
                SaalCallingNetworkReceiveConnectMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == CALLING_USER)
            {
                SaalCallingUserReceiveConnectMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == COMMON_NET_SWITCH)
            {
                SaalCommonNetworkReceiveConnectMessage(node,
                    msg, saalAppData, &prevHop, interfaceIndex);
            }
            else
            {
                // forward it towards the source
                int outIntf;
                AtmAddress nextHop;

                // It is a normal in-between switch point
                // Forward the connect packet towards the source

                outIntf = saalAppData->inIntf;
                memcpy(&nextHop, saalAppData->prevHopAddr,
                    sizeof(AtmAddress));

                AalSendSignalingMsgToLinkLayer(
                    node,
                    MESSAGE_Duplicate(node, msg),
                    saalAppData->calledPartyNum,
                    saalAppData->callingPartyNum,
                    AAL_SAAL_TTL,
                    outIntf,
                    &nextHop,
                    SAAL_CONNECT);

                saalNodeData->stats.NumOfAtmConnectSent++;
                saalAppData->state = SAAL_ACTIVE;
            }

            SaalUserUpdateVariousTables(node, saalAppData);

            // After establishing the path calling user
            // start sending buffered data

            if (saalAppData->endPointType == CALLING_USER)
            {
                Aal5CollectDataFromBuffer(node,
                    saalAppData->VCI, saalAppData->VPI);
            }

            break;
        }
    case SAAL_CONNECT_ACK:
        {
            if (DEBUG)
            {
                printf(" #%u receive ConnectAck from %x \n",
                    node->nodeId, prevHop.ESI_pt1);
            }

            // Get the Connect Ack packet
            SaalConnectAckPacket* connectAckPkt =
                (SaalConnectAckPacket*)MESSAGE_ReturnPacket(msg);

            VCI = connectAckPkt->conncId.VCI;
            VPI = connectAckPkt->conncId.VPI;

            saalAppData = SaalGetDataForThisApp(node, VCI, VPI);

            if (!saalAppData)
            {
                break;
            }

            saalNodeData->stats.NumOfAtmConnectAckRecv++;

            if (saalAppData->endPointType == CALLED_USER)
            {
                SaalCalledUserReceiveConnectAckMessage(node,
                    msg, saalAppData);

                // This node has reached to Active state
                // So it is ready for data transfer
                // And build an entry in the translation table

                SaalUpdateTransTable(node, saalAppData,
                    SAAL_INVALID_INTERFACE);
            }

            else
            {
                char errStr[MAX_STRING_LENGTH];

                // Shouldn't get here.
                sprintf(errStr,
                    "#%u: EndPt %d should not get connectAck like this\n",
                    node->nodeId, saalAppData->endPointType);
                ERROR_Assert(FALSE, errStr);
            }
            break;
        }
    case SAAL_RELEASE:
        {
            if (DEBUG)
            {
                printf(" #%u receive Release from %x \n",
                    node->nodeId, prevHop.ESI_pt1);
            }

            // Get the Release packet
            SaalReleasePacket* releasePkt =
                (SaalReleasePacket*)MESSAGE_ReturnPacket(msg);

            VCI = releasePkt->conncId.VCI;
            VPI = releasePkt->conncId.VPI;

            saalAppData = SaalGetDataForThisApp(node, VCI, VPI);

            if (!saalAppData)
            {
                break;
            }
            saalNodeData->stats.NumOfAtmReleaseRecv++;

            if (saalAppData->endPointType == CALLING_NET_SWITCH)
            {
                SaalCallingNetworkReceiveReleaseMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == CALLED_NET_SWITCH)
            {
                SaalCalledNetworkReceiveReleaseMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == CALLED_USER)
            {
                SaalCalledUserReceiveReleaseMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == COMMON_NET_SWITCH)
            {
                SaalCommonNetworkReceiveReleaseMessage(node,
                    msg, saalAppData);
            }
            else
            {
                // It's a normal point so just forward it
                int outIntf;
                AtmAddress nextHop;

                // It is a normal in-between switch point
                // so simply forward it

                outIntf = saalAppData->outIntf;
                memcpy(
                    &nextHop,
                    saalAppData->nextHopAddr,
                    sizeof(AtmAddress));

                AalSendSignalingMsgToLinkLayer(
                    node,
                    MESSAGE_Duplicate(node, msg),
                    &(atmIntf[outIntf].atmIntfAddr),
                    saalAppData->calledPartyNum,
                    AAL_SAAL_TTL,
                    outIntf,
                    &nextHop,
                    SAAL_RELEASE);

                saalNodeData->stats.NumOfAtmReleaseSent++;

                saalAppData->state = SAAL_NULL;
                SaalFreeNetworkResources(node, saalAppData);
            }
            break;
        }
    case SAAL_RELEASE_COMPLETE:
        {
            if (DEBUG)
            {
                printf(" #%u receive release complete from %x \n",
                    node->nodeId, prevHop.ESI_pt1);
            }

            // Get the Release Complete packet
            SaalReleaseCompletePacket* releaseComplPkt =
                (SaalReleaseCompletePacket*)MESSAGE_ReturnPacket(msg);

            VCI = releaseComplPkt->conncId.VCI;
            VPI = releaseComplPkt->conncId.VPI;

            saalAppData = SaalGetDataForThisApp(node, VCI, VPI);

            if (!saalAppData)
            {
                break;
            }

            saalNodeData->stats.NumOfAtmReleaseCompleteRecv++;

            if (saalAppData->endPointType == CALLING_USER)
            {
                SaalCallingUserReceiveReleaseComplMessage(node,
                    msg, saalAppData);
            }
            else if (saalAppData->endPointType == CALLED_NET_SWITCH)
            {
                SaalCalledNetworkReceiveReleaseComplMessage(node,
                    msg, saalAppData);
            }
            else if ((saalAppData->endPointType == CALLING_NET_SWITCH)
                ||(saalAppData->endPointType == COMMON_NET_SWITCH))
            {
                // This means this node is common in between
                // calling user & called user

                SaalCommonNetworkReceiveReleaseComplMessage(node,
                    msg, saalAppData);
            }
            else
            {
                char errStr[MAX_STRING_LENGTH];

                // Shouldn't get here.
                sprintf(errStr,
                    "#%u: EndPt %d should not get release compl like this\n",
                    node->nodeId, saalAppData->endPointType);
                ERROR_Assert(FALSE, errStr);
            }
            break;
        }
    default:
        {
            char errStr[MAX_STRING_LENGTH];

            // Shouldn't get here.
            sprintf(errStr, "Node %u: Got invalid saal packet %d\n",
                node->nodeId, saalMsgHdr->messageType);
            ERROR_Assert(FALSE, errStr);
        }
    }// end switch

    MESSAGE_Free(node, msg);
}


// /**
// FUNCTION    :: SaalFinalize
// LAYER       :: Adaptation Layer
// PURPOSE     :: Finalize fnction for SAAL
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void SaalFinalize(Node* node)
{
    Aal5Data* aal5Data = AalGetPtrForThisAtmNode(node);
    SaalNodeData *saalNodeData =
        (SaalNodeData *)aal5Data->saalNodeInfo;

    if (DEBUG)
    {
        SaalPrintAppList(node);
    }

    // Print out stats if user specifies it.
    if (saalNodeData->printSaalStat)
    {
        char buf[MAX_STRING_LENGTH];

        sprintf(buf, "Number of Alert Messages Sent = %d",
            saalNodeData->stats.NumOfAtmAlertSent);
        IO_PrintStat(
            node,
            "Adaptation",
            "SAAL",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Alert Messages Received = %d",
            saalNodeData->stats.NumOfAtmAlertRecv);
        IO_PrintStat(
            node,
            "Adaptation",
            "SAAL",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Connect Messages Sent = %d",
            saalNodeData->stats.NumOfAtmConnectSent);
        IO_PrintStat(
            node,
            "Adaptation",
            "SAAL",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Connect Messages Received = %d",
            saalNodeData->stats.NumOfAtmConnectRecv);
        IO_PrintStat(
            node,
            "Adaptation",
            "SAAL",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Setup Messages Sent = %d",
            saalNodeData->stats.NumOfAtmSetupSent);
        IO_PrintStat(
            node,
            "Adaptation",
            "SAAL",
            ANY_DEST,
            -1, // instance Id,
            buf);

        sprintf(buf, "Number of Setup Messages Received = %d",
            saalNodeData->stats.NumOfAtmSetupRecv);
        IO_PrintStat(
            node,
            "Adaptation",
            "SAAL",
            ANY_DEST,
            -1, // instance Id,
            buf);
    }
}
