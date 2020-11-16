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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "channel_scanner.h"
#include "app_jammer.h"
#include "phy_802_11.h"
#include "mac_dot11.h"

#ifdef WIRELESS_LIB
#include "phy_abstract.h"
#include "phy_802_11.h"
#include "mac_dot11.h"
#include "mac_dot11-sta.h"
#include "mac_generic.h"
#include "mac_csma.h"
#include "mac_tdma.h"
#endif

#ifdef ADVANCED_WIRELESS_LIB
#include "phy_dot16.h"
#endif

#ifdef SENSOR_NETWORKS_LIB
#include "mac_802_15_4.h"
#endif

static const clocktype APP_JAMMER_BURST_DURATION = 100 * MILLI_SECOND; 

AppJammer* AppJammerGetJammerInstanceOnThisInterface(Node* node, int interfaceIndex)
{
    AppInfo *appList = node->appData.appPtr;
    AppJammer *jammer;
    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_JAMMER)
        {
            jammer = (AppJammer *) appList->appDetail;

            if (jammer->interfaceIndex == interfaceIndex)
            {
                if (jammer->scannerHandle >= 0) 
                {
                    return jammer;
                }
            }
        }
    }

    return NULL;
}
AppJammer* AppJammerGetApp(Node* node, int instanceId)
{
    AppInfo *appList = node->appData.appPtr;
    AppJammer *jammer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_JAMMER)
        {
            jammer = (AppJammer *) appList->appDetail;

            if (jammer->scannerHandle == instanceId)
            {
                return jammer;
            }
        }
    }

    return NULL;
}

Message* AppJammerCreateJammerSignal(
        Node* node,
        int phyIndex,
        int channelIndex)
{
    // Step 1: Find the PHY and MAC model on this channel
    if (node->partitionData->propChannel[channelIndex].numNodes <= 0) {
        return NULL;
    }

    Node* firstListenableNode = node->partitionData->propChannel[channelIndex].nodeList[0];

    if (firstListenableNode == NULL) {
        return NULL;
    }

    PhyModel phyModel = PHY_NONE;
    MAC_PROTOCOL macProtocol = MAC_PROTOCOL_NONE;
    int phyHeaderSize;
    int macHeaderSize;

    for (int i = 0; i < firstListenableNode->numberPhys; i++)
    {
        if (firstListenableNode->phyData[i]->channelListenable[channelIndex])
        {
            PhyData* phy = firstListenableNode->phyData[i];
            MacData* mac = firstListenableNode->macData[phy->macInterfaceIndex];
            phyModel = phy->phyModel;
            macProtocol = mac->macProtocol;
           // *foundValidNode = true;
            break;
        }
    }
    /*if (*foundValidNode == false)
    {
        return NULL;
    }*/

    // Step 2: Validate that these phy and mac protocols are supported.
    // Step 3: while we are at it, find the sizes of mac and phy headers
    switch(phyModel)
    {
    case PHY802_11a:
    case PHY802_11b:
    {
        phyHeaderSize = sizeof(Phy802_11PlcpHeader);
        break;
    }
#ifdef CELLULAR_LIB
    case PHY_GSM:
    case PHY_CELLULAR:
#endif

/*#ifdef ADVANCED_WIRELESS_LIB
    case PHY802_16:
#endif*/

#ifdef SENSOR_NETWORKS_LIB
    case PHY802_15_4:
#endif
    case PHY_ABSTRACT:
    {
        phyHeaderSize = 0;
        break;
    }
    default:
        return NULL;
    }

    switch(macProtocol)
    {
#ifdef SENSOR_NETWORKS_LIB
    case MAC_PROTOCOL_802_15_4:
    {
        macHeaderSize = sizeof(M802_15_4Header);
        break;
    }
#endif

#ifdef WIRELESS_LIB
    case MAC_PROTOCOL_TDMA:
    {
        macHeaderSize = sizeof(TdmaHeader);
        break;
    }
    case MAC_PROTOCOL_CSMA:
    {
        macHeaderSize = sizeof(CsmaHeader);
        break;
    }
    case  MAC_PROTOCOL_GENERICMAC:
    {
        macHeaderSize = sizeof(GenericMacFrameHdr);
        break;
    }
    case MAC_PROTOCOL_DOT11:
    {
        macHeaderSize = sizeof(DOT11_FrameHdr);
        break;
    }
#endif
#ifdef CELLULAR_LIB
    case MAC_PROTOCOL_GSM:
    {
        macHeaderSize = 0;
        break;
    }
#endif
    default:
        return NULL;
    }


    // Step 4: Create the jammer message
    /* Jam using the current phy datarate */
    int phyTxDataRate = PHY_GetTxDataRate(node, phyIndex);
    int phyTxDataRateType = PHY_GetTxDataRateType(node, phyIndex);
    PhyData* phy = firstListenableNode->phyData[phyIndex];
    MacData* mac = firstListenableNode->macData[phy->macInterfaceIndex];

    /* Generate jamming message */
    Message *jamMsg = MESSAGE_Alloc(node, 0, 0, 0);
    if (!jamMsg)
    {
        return NULL;
    }

    /* Set jamming type */
    MESSAGE_AddInfo(node,
            jamMsg,
            sizeof(JamType),
            INFO_TYPE_JAM);

    JamType *jam_type = (JamType*)
                    MESSAGE_ReturnInfo(jamMsg, INFO_TYPE_JAM);
    *jam_type = JAM_TYPE_APP;

    /* Determine frame size needed to generate burst duration */
    int frameSz = (Int32)(phyTxDataRate *
            (double)APP_JAMMER_BURST_DURATION / SECOND / 8);

    /* Get phy + mac header sz for target */
    int hdrSz = phyHeaderSize + macHeaderSize;

    /* Set minimum frame size */
    if (frameSz <= hdrSz)
        frameSz = hdrSz + 1;

    /* Allocate frame */
    MESSAGE_PacketAlloc(node, jamMsg, frameSz - hdrSz, TRACE_JAMMER);

    /* Add mac header */
    switch(mac->macProtocol)
    {
    case MAC_PROTOCOL_GSM:
    {
        break;
    }
#ifdef SENSOR_NETWORKS_LIB
    case MAC_PROTOCOL_802_15_4:
    {
        Mac802Address destAddr = INVALID_802ADDRESS;
        MESSAGE_AddHeader(node, jamMsg, sizeof(M802_15_4Header),
                TRACE_MAC_802_15_4);
        break;
    }
#endif
    case MAC_PROTOCOL_TDMA:
    {
        Mac802Address destAddr = INVALID_802ADDRESS;
        MESSAGE_AddHeader(node, jamMsg, sizeof(TdmaHeader), TRACE_TDMA);
        TdmaHeader* hdr = (TdmaHeader *) jamMsg->packet;
        MAC_CopyMac802Address(&hdr->destAddr , &destAddr );
        ConvertVariableHWAddressTo802Address(
                node,
                &mac->macHWAddr,
                &hdr->sourceAddr);
        break;
    }
    case MAC_PROTOCOL_CSMA:
    {
        Mac802Address destAddr = INVALID_802ADDRESS;
        MESSAGE_AddHeader(node, jamMsg, sizeof(CsmaHeader), TRACE_CSMA);

        CsmaHeader* hdr = (CsmaHeader *) jamMsg->packet;
        MAC_CopyMac802Address(&hdr->destAddr , &destAddr );
        ConvertVariableHWAddressTo802Address(
                node,
                &mac->macHWAddr,
                &hdr->sourceAddr);
        break;
    }
    case MAC_PROTOCOL_GENERICMAC:
    {
        Mac802Address destAddr = INVALID_802ADDRESS;
        MESSAGE_AddHeader(node,
                jamMsg,
                sizeof(GenericMacFrameHdr),
                TRACE_GENERICMAC);

        GenericMacFrameHdr* hdr = (GenericMacFrameHdr*) MESSAGE_ReturnPacket(jamMsg);
        hdr->frameType = MGENERIC_DATA;
        MAC_CopyMac802Address(&hdr->destAddr , &destAddr );
        MAC_CopyMac802Address(&hdr->sourceAddr , &((GenericMacData*)mac->macVar)->selfAddr);
        hdr->duration = 0;
        break;
    }
    case MAC_PROTOCOL_DOT11:
    {

        MESSAGE_AddHeader(node,
                jamMsg,
                sizeof(DOT11_FrameHdr),
                TRACE_DOT11);
        DOT11_FrameHdr* hdr = (DOT11_FrameHdr*) MESSAGE_ReturnPacket(jamMsg);
        hdr->duration = 0;
        MacDot11StationSetFieldsInDataFrameHdr(( MacDataDot11*)mac->macVar,
                (DOT11_FrameHdr*) MESSAGE_ReturnPacket(jamMsg),
                INVALID_802ADDRESS,
                DOT11_DATA);

        break;
    }
    default:
        break;
    }

    /* Add phy header */
    switch(phy->phyModel)
    {
    case PHY802_11a:
    case PHY802_11b:
    {
        MESSAGE_AddHeader(node,
                jamMsg,
                sizeof(Phy802_11PlcpHeader),
                TRACE_802_11);
        Phy802_11PlcpHeader* plcp1 =
                (Phy802_11PlcpHeader*)MESSAGE_ReturnPacket(jamMsg);
        plcp1->rate = phyTxDataRateType;
        break;
    }
    case PHY_GSM:
    case PHY_CELLULAR:
    case PHY802_16: {
        /*
                           Dot16BurstInfo burstInfo;
                           memset(&burstInfo,0,sizeof(Dot16BurstInfo));
                           burstInfo.numSubchannels = 60;
                           burstInfo.numSymbols = 1;
                           MacDot16AddBurstInfo(
                           node,
                           jamMsg,
                           &burstInfo);

                           jamMsg = MESSAGE_PackMessage(node, jamMsg, TRACE_DOT16, NULL);
                           MESSAGE_AddHeader(node,
                           jamMsg,
                           sizeof(PhyDot16PlcpHeader),
                           TRACE_PHY_DOT16);
                           PhyDot16PlcpHeader *plcp = (PhyDot16PlcpHeader*)MESSAGE_ReturnPacket(jamMsg);
                           plcp->isDownlink = TRUE;
                           plcp->duration = 1;
                           break;
         */
    }
    case PHY802_15_4:
    case PHY_ABSTRACT:
    default:
        break;
    }

    return jamMsg;
}

void AppJammerStartJamming(
        Node* node,
        int interfaceIndex,
        clocktype delay,
        clocktype duration,
        int scannerIndex,
        bool silentMode,
        int minDataRate)
{
    Message* msg = MESSAGE_Alloc(
            node,
            APP_LAYER,
            APP_JAMMER,
            APP_JAMMER_START_JAMMING);

    MESSAGE_InfoAlloc(node, msg, sizeof(AppJammer));
    AppJammer* jammer = (AppJammer*) MESSAGE_ReturnInfo(msg);
    jammer->interfaceIndex = interfaceIndex;
    jammer->duration = duration;
    jammer->scannerIndex = scannerIndex;
    jammer->minDataRate = minDataRate;
    jammer->silentMode = silentMode;

    if (node->partitionData->partitionId != node->partitionId)
    {
        MESSAGE_RemoteSendSafely(node,
                        node->nodeId,
                        msg,
                        delay);
    }
    else
    {
        MESSAGE_Send(node, msg, delay);
    }
}

void AppJammerStopAllJamming(
        Node* node)
{
    Message* msg = MESSAGE_Alloc(
            node,
            APP_LAYER,
            APP_JAMMER,
            APP_JAMMER_TERMINATE_ALL);

    if (node->partitionData->partitionId != node->partitionId)
    {
        MESSAGE_RemoteSendSafely(node,
                node->nodeId,
                msg,
                0);
    }
    else
    {
        MESSAGE_Send(node, msg, 0);
    }
}

/*void AppJammerTryToStartScanning(
        Node *node,
        int channelIndex,
        AppJammer *jammer)
{
    Message* signal = jammer->signalsForChannel[channelIndex];
    bool foundValidNode = false;
    if (jammer->activeChannels[channelIndex] == false)
    {
        //the jammer on this node is already stopped, no use of retrying
        return;
    }

    if (!signal)
    {
        signal = AppJammerCreateJammerSignal(
            node,
            node->macData[jammer->interfaceIndex]->phyNumber,
            channelIndex,
            &foundValidNode);

        if (foundValidNode == false)
        {
            //printf("Don't know how to jam channel %d yet\n", channelIndex);
            Message* timer = MESSAGE_Alloc(
            node,
            APP_LAYER,
            APP_JAMMER,
            APP_JAMMER_RETRY);
            timer->instanceId = jammer->scannerHandle;
            MESSAGE_InfoAlloc(node, timer, sizeof(int));
            * (int *) MESSAGE_ReturnInfo(timer) = channelIndex;
            MESSAGE_Send(node, timer, APP_JAMMER_BURST_DURATION);
            return;
        }

        if (!signal) {
            printf("Don't know how to jam channel %d\n", channelIndex);
            return;
        }

        signal->instanceId = jammer->scannerHandle;
        signal->layerType = APP_LAYER;
        signal->protocolType = APP_JAMMER;
        signal->eventType = APP_JAMMER_SEND_JAM_SIGNAL;
        MESSAGE_InfoAlloc(node, signal, sizeof(int));
        * (int *) MESSAGE_ReturnInfo(signal) = channelIndex;

        jammer->signalsForChannel[channelIndex] = signal;
    }

    AppJammerProcessEvent(node, signal);
}*/

void AppJammerScannerCallback(
        Node* node,
        int channelIndex,
        ChannelScannerCallbackEvent event,
        void* arg)
{
    AppJammer* jammer = (AppJammer*) arg;
    printf("[%d, jammer=%d] %s channel %d at %f\n",
            node->nodeId,
            jammer->scannerHandle,
            event == CHANNEL_SCANNING_STARTED ? "START" : "STOP",
                    channelIndex,
                    1.0*node->getNodeTime()/SECOND);

    if (event == CHANNEL_SCANNING_STARTED)
    {
       /* jammer->activeChannels[channelIndex] = true;
        AppJammerTryToStartScanning(
        node,
        channelIndex,
        jammer);*/
        Message* signal = jammer->signalsForChannel[channelIndex];
        jammer->activeChannels[channelIndex] = true;

        if (!signal)
        {
            signal = AppJammerCreateJammerSignal(
                    node,
                    node->macData[jammer->interfaceIndex]->phyNumber,
                    channelIndex);

            if (!signal) {
                printf("Don't know how to jam channel %d\n", channelIndex);
                return;
            }

            signal->instanceId = jammer->scannerHandle;
            signal->layerType = APP_LAYER;
            signal->protocolType = APP_JAMMER;
            signal->eventType = APP_JAMMER_SEND_JAM_SIGNAL;
            MESSAGE_InfoAlloc(node, signal, sizeof(AppJammerJamInfo));
            AppJammerJamInfo *jamInfo = (AppJammerJamInfo *) MESSAGE_ReturnInfo(signal);
            jamInfo->duration = APP_JAMMER_BURST_DURATION;
            jamInfo->channelIndex = channelIndex;

            jammer->signalsForChannel[channelIndex] = signal;
        }

        AppJammerProcessEvent(node, signal);
    }
    else
    {
        jammer->activeChannels[channelIndex] = false;
    }
}
void AppJammerSilentScannerCallback(
        Node* node,
        int channelIndex,
        ChannelScannerCallbackEvent event,
        void* arg)
{
    AppJammer* jammer = (AppJammer*) arg;
    printf("[%d, jammer=%d] %s channel %d at %f\n",
            node->nodeId,
            jammer->scannerHandle,
            event == CHANNEL_SCANNING_STARTED ? "START" : "STOP",
                    channelIndex,
                    1.0*node->getNodeTime()/SECOND);

    if (event == CHANNEL_SCANNING_STARTED)
    {
        jammer->activeChannels[channelIndex] = true;
    }
    else
    {
        jammer->activeChannels[channelIndex] = false;
    }
}

void ResetPhyListenable(Node* node, AppJammer* jammer)
{
    //Only the last jammer instance to be running on 
    //this interface should do this 
    //because if any jammer is still active, it will need all listenable to 
    //be set, thus no change
    AppJammer *oldJammer = 
            AppJammerGetJammerInstanceOnThisInterface(node, jammer->interfaceIndex);
    if (oldJammer != NULL)
    {
        //some jammer instance is still running on this interface
        //so do nothing, just return
        return;
    }
    //If we get here,that means I am the last active jammer instance at this time
    //and since I am going to bekilled now, I need to reset the phy listenable
    PhyData *thisPhy;
    PropData* propData;
    thisPhy = node->phyData[jammer->interfaceIndex];
    for (int i = 0; i < node->numberChannels; i++) 
    {
        propData = &(node->propData[i]);
        thisPhy->channelListenable[i] = jammer->origChannelListenable[i];
        if (thisPhy->channelListenable[i] == FALSE)
        {
            propData->numPhysListenable--;
        }
        //If none of the phys(i.e. interfaces of the node) 
        //"can" listen on this channel, at this time,
        //then remove this node from the channel list
        if (propData->numPhysListenable == 0)
        {
            //propData->limitedInterference = FALSE;
            PROP_RemoveNodeFromList(node, i);
        }
    }
}

void SetPhyListenable(Node* node, AppJammer* jammer)
{
    PhyData *thisPhy;
    PropData* propData;
    thisPhy = node->phyData[jammer->interfaceIndex];
    AppJammer *oldJammer = 
            AppJammerGetJammerInstanceOnThisInterface(node, jammer->interfaceIndex);

    for (int i = 0; i < node->numberChannels; i++) 
    {
        //Check here if this node already has an active jammer 
        //instance on this interface index.
        //If it does not, then this will be the first one added
        //so get original number from this phy
        //otherwise get original number from the returned jammer instance
        
        if (oldJammer == NULL)
        {
            //This is the first jammer instance on this interface
            jammer->origChannelListenable[i] = thisPhy->channelListenable[i];
        }
        else
        {
            //This is not the first jammer instance on this interface
            jammer->origChannelListenable[i] = oldJammer->origChannelListenable[i];
            continue;
        }
        if (!PHY_CanListenToChannel(node, jammer->interfaceIndex, i))
        {
            thisPhy->channelListenable[i] = TRUE;
            propData = &(node->propData[i]);
            int origNumPhysListenable = propData->numPhysListenable;
            if (origNumPhysListenable == 0)
            {
                PROP_AddNodeToList(node, i);
            }
            propData->numPhysListenable++;
        }
    }
}

void AppJammerProcessEvent(
        Node* node,
        Message* msg)
{
    switch (msg->eventType)
    {
    case APP_JAMMER_START_JAMMING:
    {
        AppJammer* jammer = new AppJammer(*(AppJammer*)MESSAGE_ReturnInfo(msg));
        jammer->signalsForChannel = (Message**) MEM_malloc(
                sizeof(Message*) * node->partitionData->numChannels);
        memset(jammer->signalsForChannel,
                0,
                sizeof(Message*) * node->partitionData->numChannels);
        jammer->activeChannels = (bool *) MEM_malloc(
                sizeof(bool) * node->partitionData->numChannels);
        memset(jammer->activeChannels,
                0,
                sizeof(bool) * node->partitionData->numChannels);
        jammer->origChannelListenable = new D_BOOL[node->numberChannels];

        int scannerHandle;
        if (jammer->silentMode) {
            scannerHandle =
                ChannelScannerStart(
                        node,
                        "JAMMER",
                        jammer->scannerIndex,
                        AppJammerSilentScannerCallback,
                        jammer);
        } else {
            scannerHandle =
                ChannelScannerStart(
                        node,
                        "JAMMER",
                        jammer->scannerIndex,
                        AppJammerScannerCallback,
                        jammer);
        }

        if (scannerHandle < 0) {
            MEM_free(jammer->activeChannels);
            MEM_free(jammer->signalsForChannel);
            free(jammer->origChannelListenable);
            delete jammer;
            break;
        }

        //Have to call this before calling register app and setting 
        //scanner handle,
        //otherwise this same jammer will be returned as the 
        //first jammer instance on this interface always
        SetPhyListenable(node, jammer);
        APP_RegisterNewApp(node, APP_JAMMER, jammer);

        jammer->scannerHandle = scannerHandle;
        
        
        
        msg->eventType = APP_JAMMER_STOP_JAMMING;
        msg->instanceId = jammer->scannerHandle;
        if (jammer->duration == CLOCKTYPE_MAX)
        {
            break;
        }
        MESSAGE_Send(node, msg, jammer->duration);
        return;
    }
    case APP_JAMMER_STOP_JAMMING:
    {
        AppJammer* jammer = AppJammerGetApp(node, msg->instanceId);
        if (jammer == NULL) {
            break;
        }
        if (jammer->scannerHandle >= 0) {
            ChannelScannerStop(node, jammer->scannerHandle);
        }
        jammer->scannerHandle = -1;
        ResetPhyListenable(node, jammer);
        break;
    }
    case APP_JAMMER_TERMINATE_ALL:
    {
        AppInfo *appList = node->appData.appPtr;
        AppJammer *jammer;

        for (; appList != NULL; appList = appList->appNext)
        {
            if (appList->appType == APP_JAMMER)
            {
                jammer = (AppJammer *) appList->appDetail;

                if (jammer->scannerHandle >= 0) 
                {
                    ChannelScannerStop(node, jammer->scannerHandle);
                }
                jammer->scannerHandle = -1;
                ResetPhyListenable(node, jammer);
            }
        }
        break;
    }
    case APP_JAMMER_SEND_JAM_SIGNAL:
    {
        AppJammer* jammer = AppJammerGetApp(node, msg->instanceId);
        if (jammer == NULL) {
            break;
        }

        AppJammerJamInfo *jamInfo = (AppJammerJamInfo *) MESSAGE_ReturnInfo(msg);
        int channelIndex = jamInfo->channelIndex;
        clocktype duration = jamInfo->duration;

        if (jammer->activeChannels[channelIndex])
        {
            if (MAC_InterfaceIsEnabled(node, jammer->interfaceIndex))
            {
                if (jammer->signalsForChannel[channelIndex] == NULL) {
                    break;
                }

                Message* signal = MESSAGE_Duplicate(node,
                    jammer->signalsForChannel[channelIndex]);
                signal->layerType = 0;
                signal->protocolType = 0;
                signal->eventType = 0;
                signal->instanceId = 0;

                int phyIndex = node->macData[jammer->interfaceIndex]->phyNumber;
                double txPower_mW;
                PHY_GetTransmitPower(node, phyIndex, &txPower_mW);

#ifdef DEBUG0
                printf("App Jammer: at time %f node %d "
                    "sending jamming signal "
                    "with tx duration %f s\n", 
                    (double)node->getNodeTime()/SECOND,
                    node->nodeId, 
                    (double)duration/SECOND);
#endif
                PROP_ReleaseSignal(
                    node,
                    signal,
                    phyIndex,
                    channelIndex,
                    IN_DB(txPower_mW),
                    duration,
                    0);

                if (node->guiOption)
                {
                    for (int k = 0; k < 10; k++)
                    {
                        GUI_Multicast(node->nodeId,
                            GUI_PHY_LAYER,
                            //GUI_DEFAULT_DATA_TYPE,
                            GUI_EMULATION_DATA_TYPE,
                            jammer->interfaceIndex,
                            node->getNodeTime());

                    }
                }
            }

            if (!jammer->silentMode) {
                MESSAGE_Send(node, msg, APP_JAMMER_BURST_DURATION);
            }
        }
        return;
    }
    }

    MESSAGE_Free(node, msg);
}

void AppJammerFinalize(
        Node* node)
{
}
void
AppJammerCreateJammingEvent(
        Node *node, 
        AppJammer *jammer, 
        int channelIndex,
        clocktype duration,
        clocktype delay)
{
    Message* signal = jammer->signalsForChannel[channelIndex];
    
     
    if (!signal)
    {
        signal = AppJammerCreateJammerSignal(
                    node,
                    node->macData[jammer->interfaceIndex]->phyNumber,
                    channelIndex);

        if (!signal) 
        {
            printf("Don't know how to jam channel %d\n", channelIndex);
            return;
        }

        signal->instanceId = jammer->scannerHandle;
        signal->layerType = APP_LAYER;
        signal->protocolType = APP_JAMMER;
        signal->eventType = APP_JAMMER_SEND_JAM_SIGNAL;
        jammer->signalsForChannel[channelIndex] = signal;
        
        MESSAGE_InfoAlloc(node, signal, sizeof(AppJammerJamInfo));
        
    }
        
    AppJammerJamInfo *jamInfo = (AppJammerJamInfo *) MESSAGE_ReturnInfo(signal);
    jamInfo->duration = duration;
    jamInfo->channelIndex = channelIndex;
   
   AppJammerProcessEvent(node, signal);
}
void AppJammerDecideReactiveJam(
    Node* node, 
    AppJammer* jammer,
    int channelIndex,
    Message *txMsg)
{
    PropTxInfo* propTxInfo =
                        (PropTxInfo*)MESSAGE_ReturnInfo(txMsg);

#ifdef DEBUG0
    {
        int packetsize = MESSAGE_ReturnPacketSize(txMsg);
        printf("%d app_jammer: recv general packet at time %f of size %i\n",
        node->nodeId, (double)node->getNodeTime()/SECOND, packetsize);                                           
    }
#endif /* DEBUG */

    if (true) {
        // Create a message event to avoid backend simulation issues
        
        AppJammerCreateJammingEvent(
            node, 
            jammer,
            channelIndex,
            propTxInfo->duration,
            0);
            
    }
}

void AppJammerDecideJamDot11(
    Node* node, 
    AppJammer* jammer,
    int channelIndex,
    Message *txMsg)
{
    PropTxInfo* propTxInfo =
                        (PropTxInfo*)MESSAGE_ReturnInfo(txMsg);


    Phy802_11PlcpHeader* phy_hdr = (Phy802_11PlcpHeader*)MESSAGE_ReturnHeader(txMsg, 0);
    DOT11_ShortControlFrame* mac_hdr = (DOT11_ShortControlFrame*)(MESSAGE_ReturnHeader(txMsg, 0)
                                            + sizeof(Phy802_11PlcpHeader));
    if (phy_hdr == NULL || mac_hdr == NULL) {
            return;
    }
    int txDataRate;

     // Step 1: Find the PHY and MAC model on this channel
    if (node->partitionData->propChannel[channelIndex].numNodes <= 0) {
        return;
    }

    Node* firstListenableNode = node->partitionData->propChannel[channelIndex].nodeList[0];
    if (firstListenableNode == NULL) {
        return;
    }

    PhyModel phyModel = PHY_NONE;
    for (int i = 0; i < firstListenableNode->numberPhys; i++)
    {
        if (firstListenableNode->phyData[i]->channelListenable[channelIndex])
        {
            PhyData* phy = firstListenableNode->phyData[i];       
            phyModel = phy->phyModel;
            break;
        }
    }
    switch(phyModel)
    {
    case PHY802_11a:
    {
        switch(phy_hdr->rate) 
        {
        case PHY802_11a__6M:
            txDataRate =  PHY802_11a_DATA_RATE__6M;
            break;
        case PHY802_11a__9M:
            txDataRate =  PHY802_11a_DATA_RATE__9M;
            break;
        case PHY802_11a_12M:
            txDataRate =  PHY802_11a_DATA_RATE_12M;
            break;
        case PHY802_11a_18M:
            txDataRate =  PHY802_11a_DATA_RATE_18M;
            break;
        case PHY802_11a_24M:
            txDataRate =  PHY802_11a_DATA_RATE_24M;
            break;
        case PHY802_11a_36M:
            txDataRate =  PHY802_11a_DATA_RATE_36M;
            break;
        case PHY802_11a_48M:
            txDataRate =  PHY802_11a_DATA_RATE_48M;
            break;
        case PHY802_11a_54M:
            txDataRate =  PHY802_11a_DATA_RATE_54M;
            break;
        default:
            return;
        }
        break;
    }
    case PHY802_11b:
    {
        switch(phy_hdr->rate) 
        {
        case PHY802_11b__1M:
            txDataRate =  PHY802_11b_DATA_RATE__1M;
            break;
        case PHY802_11b__2M:
            txDataRate =  PHY802_11b_DATA_RATE__2M;
            break;
        case PHY802_11b__6M:
            txDataRate =  PHY802_11b_DATA_RATE__6M;
            break;
        case PHY802_11b_11M:
            txDataRate =  PHY802_11b_DATA_RATE_11M;
            break;
        default:
            return;
        }
        break;
    }
    default:
        return;
    }
  
#ifdef DEBUG0
    {
        int packetsize = MESSAGE_ReturnPacketSize(txMsg);
        printf("%d app_jammer: recv dot11 packet of type %x with rate %d at time %f of size %i\n",
        node->nodeId, mac_hdr->frameType, txDataRate, (double)node->getNodeTime()/SECOND, packetsize );                                            
    }
#endif /* DEBUG */
    if (txDataRate >= jammer->minDataRate
            && mac_hdr->frameType == DOT11_DATA
            && mac_hdr->destAddr != ANY_MAC802)
    {
        AppJammerCreateJammingEvent(
            node, 
            jammer,
            channelIndex,
            propTxInfo->duration,
            0);
            
    }
}

void AppJammerProcessReceivedSignal(
    Node* node,
    AppJammer* jammer,
    int interfaceIndex,
    int channelIndex,
    PropRxInfo *propRxInfo)
{
    /* Don't process signals from myself */
    if (propRxInfo->txNodeId == node->nodeId)
        return;

    /* Don't process if channel is not active for this jammer */
    if (!jammer->activeChannels[channelIndex])
        return;

#ifdef DEBUG0
    printf("%d app_jammer: recv signal from node %i at time %f\n",
        node->nodeId, propRxInfo->txNodeId,(double)node->getNodeTime()/SECOND);                          
#endif

    /* Switch on the first header */
    switch(propRxInfo->txMsg->headerProtocols[propRxInfo->txMsg->numberOfHeaders - 1]) 
    {
#ifdef WIRELESS_LIB
    case TRACE_802_11:
    {
        AppJammerDecideJamDot11(node, jammer, channelIndex, propRxInfo->txMsg);
        break;
    }
#endif
    default:
        AppJammerDecideReactiveJam(node, jammer, channelIndex, propRxInfo->txMsg);
        break;
    
    }
}
