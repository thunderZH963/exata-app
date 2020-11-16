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
#include <errno.h>

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#ifndef _WIN32 // unix/linux
#include <netinet/if_ether.h>
#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif
#else // windows
#include "iphlpapi.h"
#endif

#include "api.h"
#include "partition.h"
#include "external.h"
#include "external_util.h"
#include "product_info.h"
//#include "app_util.h"
//#include "external_socket.h"
//#include "network_ip.h"
//#include "app_forward.h"
//#include "network.h"

#include "auto-ipnetworkemulator.h"
#include "capture_interface.h"
#include "inject_interface.h"
#include "ipne_qualnet_interface.h"
#include "voip_interface.h"
#include "arp_interface.h"
#include "ospf_interface.h"
#include "olsr_interface.h"

#include "gui.h"
#include "record_replay.h"

#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
#include "transmission_lib.h"
#endif



//---------------------------------------------------------------------------
// External Interface API Functions
//---------------------------------------------------------------------------

// /**
// API       :: IPNE_Initialize
// PURPOSE   :: This function will allocate and initialize the
//              AutoIPNEData structure
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void AutoIPNE_Initialize(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput)
{
    AutoIPNEData* data;

    // Create new AutoIPNEData
    data = (AutoIPNEData*) MEM_malloc(sizeof(AutoIPNEData));
    memset(data, 0, sizeof(AutoIPNEData));
    iface->data = data;

    data->isAutoIPNE = true;
    data->lastReceiveTime = EXTERNAL_MAX_TIME;
    data->lastSendIntervalDelay = EXTERNAL_MAX_TIME;

    // Originally for C2Adapter
    data->partitionData = iface->partition;

    data->numArpReq = 0;
    data->numArpReceived = 0;
    data->arpRetransmission = FALSE;
    data->arpSentTime = 0;
    //data->multicastEnabled = FALSE;
    data->explictlyCalculateChecksum = FALSE;
    data->routeUnknownProtocols = FALSE;
    data->debug = FALSE;
    data->printPacketLog = FALSE;
    data->printStatistics = FALSE;
    data->lastStatisticsPrint = 0;
    data->numDevices = 0;
    data->deviceArray = NULL;
    data->precEnabled = FALSE;
    data->genericMulticastMac = FALSE;
#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
    AutoIPNE_InitializeMiQualNodeMap((AutoIPNEData*) iface->data);
    AutoIPNE_InitializeQualnetMiNodeMap((AutoIPNEData*) iface->data);
#endif
}

// /**
// API       :: AutoIPNE_MapIpv6Address
// PURPOSE   :: Try to map an Ipv6 address to an Ipv6 operational host
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// + node : Node* : Node pointer
// + interfaceIndex : Int32 : Interface index
// RETURN    :: void
// **/
void AutoIPNE_MapIpv6Address(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput,
    Node* node,
    Int32 interfaceIndex)
{
    BOOL wasFound = FALSE;
    Int8 buf[MAX_STRING_LENGTH];
    Address virtualAddress;
    virtualAddress = MAPPING_GetInterfaceAddressForInterface(
                        node,
                        node->nodeId,
                        NETWORK_IPV6,
                        interfaceIndex);
#ifdef _WIN32
    Float64 winVersion = Product::GetWindowsVersion();
    if (winVersion < WINVER_VISTA_ABOVE)
    {
        char addr1[64];
        char buf[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(&virtualAddress, addr1);
        sprintf(buf, "\nOn Windows platforms below "
        "Vista, an Ipv6 virtual node cannot be mapped "
        "to an operational host. No Mapping will occur "
        "for interface with virtual address %s\n",addr1);
        ERROR_ReportWarning(buf);
        return;
    }
#endif
     IO_ReadString(
            node->nodeId,
            &virtualAddress,
            nodeInput,
            "EXATA-EXTERNAL-NODE",
            &wasFound,
            &buf[0]);

    if (wasFound)
    {
        Address physicalAddress;
        BOOL isNodeId = FALSE;
        IO_ParseNodeIdHostOrNetworkAddress(
            buf,
            &physicalAddress,
            &isNodeId);
        if (physicalAddress.networkType != NETWORK_IPV6)
        {
            char addr1[64];
            char buf[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&virtualAddress, addr1);
            sprintf(buf, "\nCannot map non Ipv6 operational "
            "host with Ipv6 virtual address %s. No Mapping will "
            "occur for this interface\n",addr1);
            ERROR_ReportWarning(buf);
            return;
        }
        AutoIPNE_AddVirtualNode(
            iface,
            physicalAddress,
            virtualAddress,
            FALSE);
    }
}

// /**
// API       :: AutoIPNE_MapIpv4Address
// PURPOSE   :: Try to map an Ipv4 address to an Ipv4 operational host
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// + node : Node* : Node pointer
// + interfaceIndex : Int32 : Interface index
// RETURN    :: void
// **/
void AutoIPNE_MapIpv4Address(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput,
    Node* node,
    Int32 interfaceIndex)
{
    BOOL wasFound = FALSE;
    Int8 buf[MAX_STRING_LENGTH];
    Address virtualAddress;
    virtualAddress = MAPPING_GetInterfaceAddressForInterface(
                        node,
                        node->nodeId,
                        NETWORK_IPV4,
                        interfaceIndex);
    IO_ReadString(
            node->nodeId,
            &virtualAddress,
            nodeInput,
            "EXATA-EXTERNAL-NODE",
            &wasFound,
            &buf[0]);

    if (wasFound)
    {
        Address physicalAddress;
        SetIPv4AddressInfo(&physicalAddress,
            ntohl(inet_addr(buf)));
        AutoIPNE_AddVirtualNode(
            iface,
            physicalAddress,
            virtualAddress,
            FALSE);
    }
}

// /**
// API       :: AutoIPNE_InitializeNodes
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
void AutoIPNE_InitializeNodes(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    AutoIPNEData *data;
    Node *node;
    BOOL wasFound;
    int interfaceIndex;
    int debugLevel;
#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
     int jsrId;
#endif

    assert(iface != NULL);
    data = (AutoIPNEData*) iface->data;

    assert(data != NULL);

#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
    NodePointerCollectionIter nodeIter;
    for (nodeIter = iface->partition->allNodes->begin ();
            nodeIter != iface->partition->allNodes->end ();
            nodeIter++)
    {
        node = *nodeIter;

        for (interfaceIndex = 0; interfaceIndex < node->numberInterfaces; interfaceIndex++)
        {
            IO_ReadString(
                node->nodeId,
                MAPPING_GetInterfaceAddressForInterface(node, node->nodeId, interfaceIndex),
                nodeInput,
                "JSR",
                &wasFound,
                &buf[0]);

            if (wasFound)
            {
                node->isJsrNode = TRUE;                                             
                EXTERNAL_SocketInitUDP(&node->jsrSocket,node->nodeId * 1000,FALSE);
                printf("JSR is set: created the socket and binding\n");
                node->jsrSeq = 0;
            }
        }
    }
#endif

    // all virtual nodes should be in partition 0
    if (iface->partition->partitionId != iface->partition->masterPartitionForCluster)
        return;

    /* Read the debug print level */
    IO_ReadInt(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "EXTERNAL-NODE-DEBUG-LEVEL",
        &wasFound,
        &debugLevel);

    if (wasFound)
    {
        switch(debugLevel)
        {
            case 3:
                data->printPacketLog = TRUE;
            case 2:
                data->printStatistics = TRUE;
            case 1:
                data->debug = TRUE;
            default:
                ;
        }
    }

    /* Enable Packet logging (which can be compared against wireshark capture later) */

    data->packetLogCaptureSize = AutoIPNE_MIN_PACKET_CAPTURE_SIZE;

    IO_ReadInt(
            ANY_NODEID,
            ANY_ADDRESS,
            nodeInput,
            "EXTERNAL-NODE-PACKET-LOG-CAPTURE-SIZE",
            &wasFound,
            &data->packetLogCaptureSize);

    if (data->packetLogCaptureSize < AutoIPNE_MIN_PACKET_CAPTURE_SIZE)
    {
        char msg[MAX_STRING_LENGTH];
        sprintf(msg, "EXTERNAL-NODE-PACKET-LOG-CAPTURE-SIZE value set too low."
                "Should be %d minimum.", AutoIPNE_MIN_PACKET_CAPTURE_SIZE);
        ERROR_ReportError(msg);
    }

    char basename[MAX_STRING_LENGTH];
#ifdef _WIN32
    SYSTEMTIME t;
    GetLocalTime(&t);

    sprintf(basename, "packetlog-p%d-%04d%02d%02d_%02d%02d%02d",
            iface->partition->partitionId,
            t.wYear,
            t.wMonth,
            t.wDay,
            t.wHour,
            t.wMinute,
            t.wSecond);

#else /* unix/linux */

    time_t now;
    struct tm t;
    int err;

    // Break down the time into seconds, minutes, etc...
    now = time(NULL);
    localtime_r(&now, &t);

    sprintf(basename, "packetlog-p%d-%04d%02d%02d_%02d%02d%02d",
            iface->partition->partitionId,
            t.tm_year + 1900,
            t.tm_mon + 1,
            t.tm_mday,
            t.tm_hour,
            t.tm_min,
            t.tm_sec);
#endif

    IO_ReadString(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "EXTERNAL-NODE-LOG-INCOMING-PACKETS",
        &wasFound,
        buf);

    data->incomingPacketLog = FALSE;

    if (wasFound)
    {
        if (strcmp(buf, "YES") == 0)
        {
            pcap_t *logger;
            char filename[MAX_STRING_LENGTH];

            data->incomingPacketLog = TRUE;

            logger = pcap_open_dead(DLT_EN10MB, data->packetLogCaptureSize);

            if (logger == NULL)
            {
                printf("%s\n", buf);
                ERROR_ReportError("Cannot initialize pcap to dump packet logs in a file");
            }

            sprintf(filename, "%s-incoming-success.tcpdump", basename);

            data->incomingSuccessPacketLogger =
                (void *)pcap_dump_open(logger, filename);

            if (data->incomingSuccessPacketLogger == NULL)
            {
                ERROR_ReportError("Cannot open file for dumping packet log");
            }


            logger = pcap_open_dead(DLT_EN10MB, data->packetLogCaptureSize);

            if (logger == NULL)
            {
                printf("%s\n", buf);
                ERROR_ReportError("Cannot initialize pcap to dump packet logs in a file");
            }

            sprintf(filename, "%s-incoming-ignored.tcpdump", basename);

            data->incomingIgnoredPacketLogger =
                (void *)pcap_dump_open(logger, filename);

            if (data->incomingIgnoredPacketLogger == NULL)
            {
                ERROR_ReportError("Cannot open file for dumping packet log");
            }
        }
        else if (strcmp(buf, "NO") != 0)
        {
            ERROR_ReportError("EXTERNAL-NODE-INCOMING-PACKET-LOG must either be YES or NO.");

        }
    }

    IO_ReadString(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "EXTERNAL-NODE-LOG-OUTGOING-PACKETS",
        &wasFound,
        buf);

    data->outgoingPacketLog = FALSE;

    if (wasFound)
    {
        if (strcmp(buf, "YES") == 0)
        {
            pcap_t *logger;
            char filename[MAX_STRING_LENGTH];

            data->outgoingPacketLog = TRUE;

            logger = pcap_open_dead(DLT_EN10MB, data->packetLogCaptureSize);

            if (logger == NULL)
            {
                printf("%s\n", buf);
                ERROR_ReportError("Cannot initialize pcap to dump packet logs in a file");
            }

            sprintf(filename, "%s-outgoing.tcpdump", basename);

            data->outgoingPacketLogger =
                (void *)pcap_dump_open(logger, filename);

            if (data->outgoingPacketLogger == NULL)
            {
                ERROR_ReportError("Cannot open file for dumping packet log");
            }
        }
        else if (strcmp(buf, "NO") != 0)
        {
            ERROR_ReportError("EXTERNAL-NODE-OUTGOING-PACKET-LOG must either be YES or NO.");

        }
    }

    // Initialize the sniffer interface
    AutoIPNEInitializeCaptureInterface(data);
    AutoIPNEInitializeInjectInterface(data);

    data->numVirtualNodes = 0;

    // Now read any predefined virtual nodes in the config file
#ifndef JNE_BLACKSIDE_INTEROP_INTERFACE
    NodePointerCollectionIter nodeIter;
 #endif

    for (nodeIter = iface->partition->allNodes->begin ();
            nodeIter != iface->partition->allNodes->end ();
            nodeIter++)
    {
        node = *nodeIter;

        for (interfaceIndex = 0;
             interfaceIndex < node->numberInterfaces;
             interfaceIndex++)
        {
            NetworkType networkType
                = MAPPING_GetNetworkTypeFromInterface(node, interfaceIndex);
            if (networkType == NETWORK_IPV4)
            {
               AutoIPNE_MapIpv4Address(
                   iface, nodeInput, node, interfaceIndex);
            }
            else if (networkType == NETWORK_IPV6)
            {
                AutoIPNE_MapIpv6Address(
                     iface, nodeInput, node, interfaceIndex);
            }
            else if (networkType == NETWORK_DUAL)
            {
                AutoIPNE_MapIpv4Address(
                    iface, nodeInput, node, interfaceIndex);
                AutoIPNE_MapIpv6Address(
                    iface, nodeInput, node, interfaceIndex);
            }
        }
    }

    IO_ReadString(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "GENERIC-MULTICAST-MAC",
        &wasFound,
        buf);

    if (wasFound)
    {
        if (!strcmp(buf, "YES"))
            data->genericMulticastMac = TRUE;
        else
            data->genericMulticastMac = FALSE;
    }
#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
    //Call the function to create a mapping between the Qualnet Node Id and
    //the last 4 digits of the MAC address.
    JNE_CreateMIQualnetNodeMapping(iface);
#endif
}

// /**
// API       :: IPNE_Receive
// PURPOSE   :: This function will handle receive packets through libpcap
//              and sending them through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void AutoIPNE_Receive(EXTERNAL_Interface* iface)
{
    AutoIPNEData* data;

    if (iface->partition->partitionId != iface->partition->masterPartitionForCluster)
        return;

    assert(iface != NULL);
    data = (AutoIPNEData*) iface->data;
    assert(data != NULL);

    // Update average/maximum interval if this is not the first packet
    clocktype now = EXTERNAL_QueryExternalTime(iface);
    if (data->lastReceiveTime != EXTERNAL_MAX_TIME)
    {
        clocktype interval;
        interval = now - data->lastReceiveTime;
        data->avgReceiveDelayInterval +=
            (interval - data->avgReceiveDelayInterval) / 32;
        if (interval > data->maxReceiveDelayInterval)
        {
            data->maxReceiveDelayInterval = interval;
        }
    }
    data->lastReceiveTime = now;

    AutoIPNECaptureInterface(iface);

    if (now - data->lastStatisticsPrint > AutoIPNE_DEFAULT_STATISTICS_INTERVAL)
    {
        double nowInDouble = 1.0 * now / SECOND;
        bool showDropWarning = false;

        for (int i = 0; i < AUTO_IPNE_STATS_SIZE/2; i++)
        {
            // Assuming that local and cumulative stats are
            // next to each other in the enum
            data->stats[2*i+1] += data->stats[2*i];
        }

        if (data->printStatistics)
        {
            printf("EXata Statistics at %.3f sec\n",
                (double) EXTERNAL_QuerySimulationTime(iface) / SECOND);

            printf("    Deviation from Real Time = +%.3f sec\n",
                (double) (now - EXTERNAL_QuerySimulationTime(iface)) / SECOND);

            printf("    External Interface Capture Lag = %.3f +- %.3f ms\n",
                (double) data->avgReceiveDelayInterval / MILLI_SECOND
                    - 1 * iface->receiveCallDelay / MILLI_SECOND,
                (double) data->jitter / MILLI_SECOND);

            printf("    Device Capture Statistics:: (this period/cumulative)\n");
        }

        // Print the pcap statistics
        for (int i = 0; i < data->numDevices; i++)
        {
            if (data->deviceArray[i].disabled)
                continue;
            if (data->deviceArray[i].mappingsList == NULL)
                continue;

            struct pcap_stat stat;
            pcap_stats(data->deviceArray[i].pcapFrame, &stat);
            if (data->printStatistics)
            {
                printf("      Device:%-8s "
                       "Received(this period/cumulative)=%u/%u     "
                       "Dropped(this period/cumulative)=%u/%u\n",
                        data->deviceArray[i].device,
                        stat.ps_recv - data->deviceArray[i].received,
                        stat.ps_recv,
                        stat.ps_drop - data->deviceArray[i].dropped,
                        stat.ps_drop);
            }

            if (data->deviceArray[i].dropped != stat.ps_drop)
            {
                showDropWarning = true;
            }

            data->deviceArray[i].received = stat.ps_recv;
            data->deviceArray[i].dropped  = stat.ps_drop;
        }

        if (data->printStatistics)
        {
            printf("    All Traffic Statistics (this period/cumulative)::\n");
            printf("        IN::   Packets=%lu/%lu  Pkts/sec=%.2f/%.2f  "
                    "Bytes=%lu/%lu  Bytes/sec=%.2f/%.2f\n",
                    data->stats[AUTO_IPNE_STATS_ALL_IN_PKT],
                    data->stats[AUTO_IPNE_STATS_ALL_IN_PKT_CUMM],
                    data->stats[AUTO_IPNE_STATS_ALL_IN_PKT] / 3.0,
                    data->stats[AUTO_IPNE_STATS_ALL_IN_PKT_CUMM] / nowInDouble,
                    data->stats[AUTO_IPNE_STATS_ALL_IN_BYTES],
                    data->stats[AUTO_IPNE_STATS_ALL_IN_BYTES_CUMM],
                    data->stats[AUTO_IPNE_STATS_ALL_IN_BYTES] / 3.0,
                    data->stats[AUTO_IPNE_STATS_ALL_IN_BYTES_CUMM] / nowInDouble);
            printf("        OUT::  Packets=%lu/%lu  Pkts/sec=%.2f/%.2f  "
                    "Bytes=%lu/%lu  Bytes/sec=%.2f/%.2f\n",
                    data->stats[AUTO_IPNE_STATS_ALL_OUT_PKT],
                    data->stats[AUTO_IPNE_STATS_ALL_OUT_PKT_CUMM],
                    data->stats[AUTO_IPNE_STATS_ALL_OUT_PKT] / 3.0,
                    data->stats[AUTO_IPNE_STATS_ALL_OUT_PKT_CUMM] / nowInDouble,
                    data->stats[AUTO_IPNE_STATS_ALL_OUT_BYTES],
                    data->stats[AUTO_IPNE_STATS_ALL_OUT_BYTES_CUMM],
                    data->stats[AUTO_IPNE_STATS_ALL_OUT_BYTES] / 3.0,
                    data->stats[AUTO_IPNE_STATS_ALL_OUT_BYTES_CUMM] / nowInDouble);

            printf("    Application Traffic Statistics::\n");
            printf("      Packets IN (this period/cumulative)\n");
            printf("        TCP::\tPackets=%lu/%lu  Pkts/sec=%.2f/%.2f  "
                    "Bytes=%lu/%lu  Bytes/sec=%.2f/%.2f\n",
                    data->stats[AUTO_IPNE_STATS_TCP_IN_PKT],
                    data->stats[AUTO_IPNE_STATS_TCP_IN_PKT_CUMM],
                    data->stats[AUTO_IPNE_STATS_TCP_IN_PKT] / 3.0,
                    data->stats[AUTO_IPNE_STATS_TCP_IN_PKT_CUMM] / nowInDouble,
                    data->stats[AUTO_IPNE_STATS_TCP_IN_BYTES],
                    data->stats[AUTO_IPNE_STATS_TCP_IN_BYTES_CUMM],
                    data->stats[AUTO_IPNE_STATS_TCP_IN_BYTES] / 3.0,
                    data->stats[AUTO_IPNE_STATS_TCP_IN_BYTES_CUMM] / nowInDouble);
            printf("        UDP::\tPackets=%lu/%lu  Pkts/sec=%.2f/%.2f  "
                    "Bytes=%lu/%lu  Bytes/sec=%.2f/%.2f\n",
                    data->stats[AUTO_IPNE_STATS_UDP_IN_PKT],
                    data->stats[AUTO_IPNE_STATS_UDP_IN_PKT_CUMM],
                    data->stats[AUTO_IPNE_STATS_UDP_IN_PKT] / 3.0,
                    data->stats[AUTO_IPNE_STATS_UDP_IN_PKT_CUMM] / nowInDouble,
                    data->stats[AUTO_IPNE_STATS_UDP_IN_BYTES],
                    data->stats[AUTO_IPNE_STATS_UDP_IN_BYTES_CUMM],
                    data->stats[AUTO_IPNE_STATS_UDP_IN_BYTES] / 3.0,
                    data->stats[AUTO_IPNE_STATS_UDP_IN_BYTES_CUMM] / nowInDouble);
            printf("        Total::\tPackets=%lu/%lu  Pkts/sec=%.2f/%.2f  "
                    "Bytes=%lu/%lu  Bytes/sec=%.2f/%.2f\n",
                    data->stats[AUTO_IPNE_STATS_TCP_IN_PKT] +
                    data->stats[AUTO_IPNE_STATS_UDP_IN_PKT],
                    data->stats[AUTO_IPNE_STATS_TCP_IN_PKT_CUMM] +
                    data->stats[AUTO_IPNE_STATS_UDP_IN_PKT_CUMM],
                    data->stats[AUTO_IPNE_STATS_TCP_IN_PKT] / 3.0 +
                    data->stats[AUTO_IPNE_STATS_UDP_IN_PKT] / 3.0,
                    data->stats[AUTO_IPNE_STATS_TCP_IN_PKT_CUMM] / nowInDouble +
                    data->stats[AUTO_IPNE_STATS_UDP_IN_PKT_CUMM] / nowInDouble,
                    data->stats[AUTO_IPNE_STATS_TCP_IN_BYTES] +
                    data->stats[AUTO_IPNE_STATS_UDP_IN_BYTES],
                    data->stats[AUTO_IPNE_STATS_TCP_IN_BYTES_CUMM] +
                    data->stats[AUTO_IPNE_STATS_UDP_IN_BYTES_CUMM],
                    data->stats[AUTO_IPNE_STATS_TCP_IN_BYTES] / 3.0 +
                    data->stats[AUTO_IPNE_STATS_UDP_IN_BYTES] / 3.0,
                    data->stats[AUTO_IPNE_STATS_TCP_IN_BYTES_CUMM] / nowInDouble +
                    data->stats[AUTO_IPNE_STATS_UDP_IN_BYTES_CUMM] / nowInDouble);

            printf("      Packets OUT (this period/cumulative)\n");
            printf("        TCP::\tPackets=%lu/%lu  Pkts/sec=%.2f/%.2f  "
                    "Bytes=%lu/%lu  Bytes/sec=%.2f/%.2f\n",
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_PKT],
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_PKT_CUMM],
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_PKT] / 3.0,
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_PKT_CUMM] / nowInDouble,
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_BYTES],
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_BYTES_CUMM],
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_BYTES] / 3.0,
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_BYTES_CUMM] / nowInDouble);
            printf("        UDP::\tPackets=%lu/%lu  Pkts/sec=%.2f/%.2f  "
                    "Bytes=%lu/%lu  Bytes/sec=%.2f/%.2f\n",
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_PKT],
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_PKT_CUMM],
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_PKT] / 3.0,
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_PKT_CUMM] / nowInDouble,
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_BYTES],
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_BYTES_CUMM],
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_BYTES] / 3.0,
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_BYTES_CUMM] / nowInDouble);
            printf("        Total::\tPackets=%lu/%lu  Pkts/sec=%.2f/%.2f  "
                    "Bytes=%lu/%lu  Bytes/sec=%.2f/%.2f\n",
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_PKT] +
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_PKT],
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_PKT_CUMM] +
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_PKT_CUMM],
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_PKT] / 3.0 +
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_PKT] / 3.0,
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_PKT_CUMM] / nowInDouble +
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_PKT_CUMM] / nowInDouble,
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_BYTES] +
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_BYTES],
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_BYTES_CUMM] +
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_BYTES_CUMM],
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_BYTES] / 3.0 +
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_BYTES] / 3.0,
                    data->stats[AUTO_IPNE_STATS_TCP_OUT_BYTES_CUMM] / nowInDouble +
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_BYTES_CUMM] / nowInDouble);


            printf("    Multicast Traffic Statistics (this period/cumulative)::\n");
            printf("        IN::   Packets=%lu/%lu  Pkts/sec=%.2f/%.2f  "
                    "Bytes=%lu/%lu  Bytes/sec=%.2f/%.2f\n",
                    data->stats[AUTO_IPNE_STATS_MULTI_IN_PKT],
                    data->stats[AUTO_IPNE_STATS_MULTI_IN_PKT_CUMM],
                    data->stats[AUTO_IPNE_STATS_MULTI_IN_PKT] / 3.0,
                    data->stats[AUTO_IPNE_STATS_MULTI_IN_PKT_CUMM] / nowInDouble,
                    data->stats[AUTO_IPNE_STATS_MULTI_IN_BYTES],
                    data->stats[AUTO_IPNE_STATS_MULTI_IN_BYTES_CUMM],
                    data->stats[AUTO_IPNE_STATS_MULTI_IN_BYTES] / 3.0,
                    data->stats[AUTO_IPNE_STATS_MULTI_IN_BYTES_CUMM] / nowInDouble);
            printf("        OUT::  Packets=%lu/%lu  Pkts/sec=%.2f/%.2f  "
                    "Bytes=%lu/%lu  Bytes/sec=%.2f/%.2f\n",
                    data->stats[AUTO_IPNE_STATS_MULTI_OUT_PKT],
                    data->stats[AUTO_IPNE_STATS_MULTI_OUT_PKT_CUMM],
                    data->stats[AUTO_IPNE_STATS_MULTI_OUT_PKT] / 3.0,
                    data->stats[AUTO_IPNE_STATS_MULTI_OUT_PKT_CUMM] / nowInDouble,
                    data->stats[AUTO_IPNE_STATS_MULTI_OUT_BYTES],
                    data->stats[AUTO_IPNE_STATS_MULTI_OUT_BYTES_CUMM],
                    data->stats[AUTO_IPNE_STATS_MULTI_OUT_BYTES] / 3.0,
                    data->stats[AUTO_IPNE_STATS_MULTI_OUT_BYTES_CUMM] / nowInDouble);

            for (int i = 0; i < AUTO_IPNE_STATS_SIZE/2; i++)
            {
                data->stats[2*i] = 0;
            }
        }

        if (showDropWarning)
        {
            printf("WARNING:: Some packets were dropped by the EXata packet capture interface.\n"
                        "Possibly due to excessive input traffic load.\n");
        }
        data->lastStatisticsPrint = now;
    }

}

// /**
// API       :: AutoIPNE_Forward
// PURPOSE   :: This function will inject a packet back into the physical
//              network once it has travelled through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + forwardData : void* : A pointer to the data to forward
// + forwardSize : int : The size of the data
// RETURN    :: void
// **/
void AutoIPNE_Forward(
    EXTERNAL_Interface* iface,
    Node *node,
    void* forwardData,
    int forwardSize)
{
}

// /**
// API       :: AutoIPNE_Finalize
// PURPOSE   :: This function will finalize the libpcap and libnet libraries
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void AutoIPNE_Finalize(EXTERNAL_Interface* iface)
{
    AutoIPNEData *data;
    data = (AutoIPNEData *)iface->data;

    if (data->incomingPacketLog)
    {
        pcap_dump_close((pcap_dumper_t *)data->incomingSuccessPacketLogger);
        pcap_dump_close((pcap_dumper_t *)data->incomingIgnoredPacketLogger);
    }
    if (data->outgoingPacketLog)
    {
        pcap_dump_close((pcap_dumper_t *)data->outgoingPacketLogger);
    }
}

// API       :: CheckOperationalHostConnectivityIpv6
// PURPOSE   :: This function is used to check the connectivity with an
//              IPv6 operational host from EXata emulation server and resolve
//              the mac address of the operational host
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + data : AutoIPNEData* : Pointer to the AutoIPNEData
// + virtualAddress : Address : Virtual Address of mapped EXata node
// + physicalAddress : Address  : Physical address of operational host
// + macAddress : Int8* : Pointer to array which stores the MAC address
// + macAddressSize : Int32* : Pointer to size of MAC address
// + deviceIndex : Int32* : Pointer to device index of physical interface
// + isVirtualLan : BOOL* : Pointer to variable that determines if its a
//                          virtual lan configuration
// RETURN :: BOOL : TRUE when successfully able to determine MAC addresss
//                  FALSE otherwise
static BOOL CheckOperationalHostConnectivityIpv6(
    EXTERNAL_Interface* iface,
    AutoIPNEData* data,
    Address virtualAddress,
    Address physicalAddress,
    Int8* macAddress,
    Int32* macAddressSize,
    Int32* deviceIndex,
    BOOL* isVirtualLan)
{
    AutoIPNE_NodeMapping* mapping = NULL;
    BOOL macAddressResolved = FALSE;
    BOOL deviceFound = FALSE;
    Int32 i = 0;
    Int32 err = 1;
    Int32 valueSize = 0;

    // Find out which device is connected to this operational node
    list<AutoIpneV4V6Address>::iterator it;
    for (i = 0; i < data->numDevices; i++)
    {
        if (data->deviceArray[i].disabled)
            continue;

        it = data->deviceArray[i].interfaceAddress->begin();
        for (; it != data->deviceArray[i].interfaceAddress->end(); ++it)
        {
            if (it->address.networkType == NETWORK_IPV6)
            {
                UInt8 sizeOfSubnetAddress
                    = it->u.ipv6.OnLinkPrefixLength / 8;
                if (memcmp(it->address.interfaceAddr.ipv6.s6_addr,
                           physicalAddress.interfaceAddr.ipv6.s6_addr,
                           sizeOfSubnetAddress) == 0)
                {
                    if (memcmp(it->address.interfaceAddr.ipv6.s6_addr,
                               physicalAddress.interfaceAddr.ipv6.s6_addr,
                               sizeof(physicalAddress.interfaceAddr.ipv6)) == 0)
                    {
                        Int8 addr1[64];
                        Int8 msg[MAX_STRING_LENGTH];
                        IO_ConvertIpAddressToString(&virtualAddress,
                                                    addr1);
                        sprintf(msg, "Virtual node %s is mapped with one "
                                     "of the IPv6 address of the machine "
                                     "on which EXata server is running. "
                                     "Virtual Lan configuration is "
                                     "currently not supported.",addr1);
                        ERROR_ReportError(msg);
                    }

                    deviceFound = TRUE;
                    *deviceIndex = i;

                    // Get the MAC address of operational host
                    err =  DetermineOperationHostMACAddressIpv6(
                            data,
                            GetIPv6Address(it->address),
                            it->u.ipv6.scopeId,
                            physicalAddress.interfaceAddr.ipv6,
                            macAddress,
                            macAddressSize,
                            *deviceIndex);

                    if (!err)
                    {
                        if (data->debug)
                        {
                            char addr1[64];
                            char addr2[64];
                            IO_ConvertIpAddressToString(&physicalAddress,
                                                        addr1);
                            IO_ConvertIpAddressToString(&it->address, addr2);
                            printf("\n%s %s %s %s\n","MAC address resolution"
                                " failed for operation host",addr1,
                                "via device IP address", addr2);
                        }
                        *deviceIndex = -1;
                        continue;
                    }
                    else
                    {
                        Int8 macKey[10];
                        BOOL success = FALSE;
                        Int32 macKeySize
                            = *macAddressSize + sizeof(*deviceIndex);
                        success
                            = AutoIPNE_CreateMacKey(macKey,
                                                    macAddress,
                                                    *deviceIndex);
                        if (!success)
                        {
                            ERROR_ReportWarning("Cannot create a mapping\n");
                        }
                        else
                        {
                            err = EXTERNAL_ResolveMapping(
                                            iface,
                                            macKey,
                                            macKeySize,
                                            (Int8**)&mapping,
                                            &valueSize);
                            if (!err)
                            {
                                char addr1[64];
                                Int8 macAddressString[18];
                                sprintf(macAddressString,
                                        "%02x:%02x:%02x:%02x:%02x:%02x",
                                        (UInt8) macAddress[0],
                                        (UInt8) macAddress[1],
                                        (UInt8) macAddress[2],
                                        (UInt8) macAddress[3],
                                        (UInt8) macAddress[4],
                                        (UInt8) macAddress[5]);
                                IO_ConvertIpAddressToString(
                                    &virtualAddress,
                                    addr1);
                                Int8 buf[MAX_STRING_LENGTH];
                                sprintf(buf,"\nAn operational host with "
                                 "MAC address %s already connected to "
                                 "EXata. Not mapping virtual node with "
                                 "address %s",macAddressString, addr1);
                                ERROR_ReportWarning(buf);
                                return FALSE;
                            }
                        }
                        macAddressResolved = TRUE;
                        break;
                    }
                }
            }
        }
        if (macAddressResolved)
        {
            break;
        }
    }

    if (!deviceFound)
    {
        Int8 addr1[64];
        Int8 msg[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(&physicalAddress, addr1);
        sprintf(msg, "Cannot find a network interface on this machine that"
                     " can connect to the operational host %s",addr1);
        ERROR_ReportWarning(msg);
        return FALSE;
    }

    if (!macAddressResolved)
    {
        Int8 addr1[64];
        Int8 msg[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(&physicalAddress, addr1);
        sprintf(msg, "Cannot find MAC address of the operational node %s,"
            "Disabling this operational host (traffic will not be received "
            "from the operational host).", addr1);
        ERROR_ReportError(msg);
        return FALSE;
    }

     if (data->debug)
    {
        char addr1[64];
        char addr2[64];
        IO_ConvertIpAddressToString(&physicalAddress, addr1);
        IO_ConvertIpAddressToString(&it->address, addr2);
        printf("\n%s %s %s %s","MAC address resolution successful"
            " for operation host",addr1, "via device IP address", addr2);
    }

     // Virtual lan configuration is currently not supported for Ipv6 network
     *isVirtualLan = FALSE;
     return TRUE;
}

// API       :: CheckOperationalHostConnectivityIpv4
// PURPOSE   :: This function is used to check the connectivity with an
//              IPv4 operational host from EXata emulation server and resolve
//              the mac address of the operational host
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + data : AutoIPNEData* : Pointer to the AutoIPNEData
// + virtualNodePtr : Node* : Pointer to the node
// + virtualAddress : Address : Virtual Address of mapped EXata node
// + physicalAddress : Address  : Physical address of operational host
// + macAddress : Int8* : Pointer to array which stores the MAC address
// + macAddressSize : Int32* : Pointer to size of MAC address
// + deviceIndex : Int32* : Pointer to device index of physical interface
// + isVirtualLan : BOOL* : Pointer to variable that determines if its a
//                          virtual lan configuration
// RETURN :: BOOL : TRUE when successfully able to determine MAC addresss
//                  FALSE otherwise
static BOOL CheckOperationalHostConnectivityIpv4(
    EXTERNAL_Interface* iface,
    AutoIPNEData* data,
    Node* virtualNodePtr,
    Address virtualAddress,
    Address physicalAddress,
    Int8* macAddress,
    Int32* macAddressSize,
    Int32* deviceIndex,
    BOOL* isVirtualLan)
{
    AutoIPNE_NodeMapping* mapping = NULL;
    BOOL macAddressResolved = FALSE;
    BOOL deviceFound = FALSE;
    Int32 i = 0;
    Int32 err = 1;
    Int32 valueSize = 0;
    list<AutoIpneV4V6Address>::iterator it;
    for (*deviceIndex = -1, i = 0; i < data->numDevices; i++)
    {
        if (data->deviceArray[i].disabled)
            continue;

        it = data->deviceArray[i].interfaceAddress->begin();
        for (; it != data->deviceArray[i].interfaceAddress->end(); ++it)
        {
            if (it->address.networkType == NETWORK_IPV4)
            {
                if ((it->address.interfaceAddr.ipv4 & it->u.subnetmask)
                    == (physicalAddress.interfaceAddr.ipv4 & it->u.subnetmask))
                {
                    *deviceIndex = i;
                    break;
                }
            }
        }
        if (*deviceIndex != -1)
            break;
    }

    if (*deviceIndex == -1)
    {
        char msg[MAX_STRING_LENGTH];
        sprintf(msg, "Cannot find a network interface on this machine that "
                "can connect to the operational host %x\n",
                htonl(physicalAddress.interfaceAddr.ipv4));
        ERROR_ReportWarning(msg);
        return FALSE;
    }

    if (physicalAddress.interfaceAddr.ipv4 == it->address.interfaceAddr.ipv4)
    {
        *isVirtualLan = TRUE;
        iface->partition->virtualLanGateways->insert(
            std::pair<int, int>(ntohl(physicalAddress.interfaceAddr.ipv4),
            ntohl(it->u.subnetmask)));

        // tell all other partitions that there is a virtual LAN gateway
        if (iface->partition->getNumPartitions() > 1)
        {
            Message* msg = MESSAGE_Alloc(iface->partition->firstNode,
                                    EXTERNAL_LAYER,
                                    EXTERNAL_IPNE,
                                    EXTERNAL_MESSAGE_IPNE_SetVirtualLanGateway);
            MESSAGE_PacketAlloc(virtualNodePtr, msg, sizeof(int) * 2, TRACE_IP);
            int *packet = (int *)MESSAGE_ReturnPacket(msg);
            *packet = ntohl(physicalAddress.interfaceAddr.ipv4);
            *(packet + 1) = ntohl(it->u.subnetmask);

            for (int i = 0; i < iface->partition->getNumPartitions(); i++)
            {
                if (i == iface->partition->partitionId)
                {
                    continue;
                }

                EXTERNAL_MESSAGE_RemoteSend(iface,
                        i,
                        MESSAGE_Duplicate(iface->partition->firstNode, msg),
                        0,
                        EXTERNAL_SCHEDULE_LOOSELY);
            }
            MESSAGE_Free(iface->partition->firstNode, msg);
        }
    }

    err = DetermineOperationHostMACAddress(data,
            physicalAddress.interfaceAddr.ipv4,
            macAddress,
            macAddressSize,
            *deviceIndex);
    if (!err)
    {
        char msg[MAX_STRING_LENGTH];
        sprintf(msg, "Cannot find MAC address of the operational node %x,"
            "Disabling this operational host(traffic will not be received "
            "from the operational host).",
            htonl(physicalAddress.interfaceAddr.ipv4));
        ERROR_ReportError(msg);
        return FALSE;
    }
    return TRUE;
}


// /**
// API       :: AutoIPNE_AddVirtualNode
// PURPOSE   :: This function maps an IPv6 virtual address with an Ipv6
//              physical address
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + physicalAddress : Address : Ipv6 address of operational
//                         host
// + virtualAddress : Address : Ipv6 address of virtual node
// + routingDisabled : BOOL : is routing disabled
// RETURN    :: BOOL : Whether mapping was successful or not
// **/
BOOL AutoIPNE_AddVirtualNode(
    EXTERNAL_Interface* iface,
    Address physicalAddress,
    Address virtualAddress,
    BOOL routingDisabled)
{
    Int32 i = 0, deviceIndex = -1;
    AutoIPNEData* data = NULL;
    AutoIPNE_NodeMapping* mapping = NULL;
    Int32 err = 1, valueSize = 0;
    BOOL macAddressResolved = FALSE;
    Int8 macAddress[6];
    Int32 macAddressSize = 0;
    BOOL deviceFound = FALSE;

    BOOL isIpv4Mode = FALSE;
    Int32 keySize = 0;
    Int8* virtualAddressPtr = NULL;
    Int8* physicalAddressPtr = NULL;

    Int32 nodeId = 0;
    Node* virtualNodePtr = NULL;
    Int32 interfaceIndex = 0;

    data = (AutoIPNEData*)iface->data;

    if (!data->isAutoIPNE)
    {
        ERROR_ReportWarning("Connection Manager does not work with"
                            " Legacy IPNE");
        return FALSE;
    }

    // Get the node pointer (from virtual address)
    nodeId = MAPPING_GetNodeIdFromInterfaceAddress(
            iface->partition->firstNode,
            virtualAddress);
    if (nodeId == INVALID_ADDRESS)
    {
        char msg[MAX_STRING_LENGTH];
        sprintf(msg, "Invalid virtual node address: ipv6\n");
        ERROR_ReportWarning(msg);
        return false;
    }

    virtualNodePtr
        = MAPPING_GetNodePtrFromHash(iface->partition->nodeIdHash, nodeId);
    if (virtualNodePtr == NULL)
    {
        virtualNodePtr = MAPPING_GetNodePtrFromHash(
                iface->partition->remoteNodeIdHash,
                nodeId);
        if (virtualNodePtr == NULL)
        {
            char msg[MAX_STRING_LENGTH];
            sprintf(msg, "Invalid virtual node address: ipv6 or nodeId: %d\n",
                    nodeId);
            ERROR_ReportWarning(msg);
            return false;
        }
    }

    interfaceIndex
        = MAPPING_GetInterfaceIndexFromInterfaceAddress(virtualNodePtr,
                                                        virtualAddress);

    virtualAddressPtr = (Int8*)&virtualAddress.interfaceAddr;
    physicalAddressPtr = (Int8*)&physicalAddress.interfaceAddr;

    if (virtualAddress.networkType == NETWORK_IPV4)
    {
        isIpv4Mode = TRUE;
        keySize = sizeof(NodeAddress);

        // Convert the address in network format
        virtualAddress.interfaceAddr.ipv4
            = htonl(virtualAddress.interfaceAddr.ipv4);
        physicalAddress.interfaceAddr.ipv4
            = htonl(physicalAddress.interfaceAddr.ipv4);
    }
    else
    {
        keySize = sizeof(in6_addr);
    }


    // Validate if the mappings for the virtual address and physical
    // address already exist

    err = EXTERNAL_ResolveMapping(
                iface,
                virtualAddressPtr,
                keySize,
                (Int8**) &mapping,
                &valueSize);

    // AutoIPNE_NodeMapping

    if (!err)
    {
        char addr1[64];
        char buf[MAX_STRING_LENGTH];
        Address tmpAddress;
        tmpAddress = virtualAddress;
        if (isIpv4Mode)
        {
            tmpAddress.interfaceAddr.ipv4
                = ntohl(tmpAddress.interfaceAddr.ipv4);
        }
        IO_ConvertIpAddressToString(&tmpAddress, addr1);
        sprintf(buf, "A mapping already exists for the virtual address: %s"
                " (by operation host ",
                addr1);

        tmpAddress = mapping->physicalAddress;
        if (isIpv4Mode)
        {
            tmpAddress.interfaceAddr.ipv4
                    = ntohl(tmpAddress.interfaceAddr.ipv4);
        }
        IO_ConvertIpAddressToString(&tmpAddress, addr1);
        sprintf(buf, "%s%s)\n", buf, addr1);
        ERROR_ReportWarning(buf);

        if (!memcmp(&mapping->physicalAddress.interfaceAddr,
                    physicalAddressPtr,
                    keySize))
        {
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }

    err = EXTERNAL_ResolveMapping(
                iface,
                physicalAddressPtr,
                keySize,
                (Int8**) &mapping,
                &valueSize);

    if (!err)
    {
        char addr1[64];
        char buf[MAX_STRING_LENGTH];
        Address tempAddress = physicalAddress;
        if (isIpv4Mode)
        {
            tempAddress.interfaceAddr.ipv4
                = ntohl(tempAddress.interfaceAddr.ipv4);
        }
        IO_ConvertIpAddressToString(&tempAddress, addr1);
        sprintf(buf, "Operational host %s already connected to EXata. "
            " Not mapping virtual address ",addr1);
        tempAddress = virtualAddress;
        if (isIpv4Mode)
        {
            tempAddress.interfaceAddr.ipv4
                = ntohl(tempAddress.interfaceAddr.ipv4);
        }
        IO_ConvertIpAddressToString(&tempAddress, addr1);
        sprintf(buf, "%s%s\n", buf, addr1);
        ERROR_ReportWarning(buf);
        return FALSE;
    }

    if (data->debug)
    {
        char addr1[64];
        Address tempAddress = physicalAddress;
        if (isIpv4Mode)
        {
            tempAddress.interfaceAddr.ipv4
                = ntohl(tempAddress.interfaceAddr.ipv4);
        }
        IO_ConvertIpAddressToString(&tempAddress, addr1);
        printf("\nResolving MAC address for operation host %s",addr1);
     }

    BOOL status = TRUE;
    BOOL isVirtualLan = FALSE;
    if (isIpv4Mode)
    {
        status =  CheckOperationalHostConnectivityIpv4(
                iface,
                data,
                virtualNodePtr,
                virtualAddress,
                physicalAddress,
                macAddress,
                &macAddressSize,
                &deviceIndex,
                &isVirtualLan);
    }
    else
    {
        status = CheckOperationalHostConnectivityIpv6(
            iface,
            data,
            virtualAddress,
            physicalAddress,
            macAddress,
            &macAddressSize,
            &deviceIndex,
            &isVirtualLan);
    }

    if (!status)
    {
        return FALSE;
    }

    // Create NodeMapping for this virtual node
    mapping
        = (AutoIPNE_NodeMapping*)MEM_malloc(sizeof(AutoIPNE_NodeMapping));
    memset(mapping, 0, sizeof(AutoIPNE_NodeMapping));


    mapping->deviceIndex = deviceIndex;
    mapping->physicalAddress = physicalAddress;
    mapping->virtualAddress = virtualAddress;
    memcpy(mapping->macAddress, macAddress, macAddressSize);
    mapping->macAddressSize = macAddressSize;
    mapping->isVirtualLan = isVirtualLan;

    sprintf(
            mapping->macAddressString,
            "%02x:%02x:%02x:%02x:%02x:%02x",
                (UInt8) mapping->macAddress[0],
                (UInt8) mapping->macAddress[1],
                (UInt8) mapping->macAddress[2],
                (UInt8) mapping->macAddress[3],
                (UInt8) mapping->macAddress[4],
                (UInt8) mapping->macAddress[5]);

    // Check if NAT should be enabled
    if (!memcmp(physicalAddressPtr, virtualAddressPtr, keySize))
    {
        if (routingDisabled)
        {
            mapping->ipneMode = AUTO_IPNE_MODE_NAT_DISABLED_ROUTING_DISABLED;
        }
        else
        {
            mapping->ipneMode = AUTO_IPNE_MODE_NAT_DISABLED_ROUTING_ENABLED;
        }
    }
    else
    {
        mapping->ipneMode = AUTO_IPNE_MODE_NAT_ENABLED;
    }

    mapping->node = virtualNodePtr;
    mapping->interfaceIndex = interfaceIndex;

    // Insert this mapping in the hash table

    // Mapping for virtual address
    EXTERNAL_CreateMapping(
            iface,
            virtualAddressPtr,
            keySize,
            (Int8*) mapping,
            sizeof(AutoIPNE_NodeMapping));

    // Mapping for physical address
    if (mapping->ipneMode == AUTO_IPNE_MODE_NAT_ENABLED)
    {
        EXTERNAL_CreateMapping(
                iface,
                physicalAddressPtr,
                keySize,
                (char*) mapping,
                sizeof(AutoIPNE_NodeMapping));
    }

    /* Mapping for macAddress
     * Key in the mapping table is not the macAddress alone but also the
     * corresponding device index. This is required to ensure that more than
     * 1 physical interface with the same MAC address can be stored without
     * any collisions
     */

    Int8 macKey[10];
    BOOL success = FALSE;
    Int32 macKeySize = mapping->macAddressSize + sizeof(deviceIndex);
    success = AutoIPNE_CreateMacKey(macKey,mapping->macAddress,deviceIndex);
    if (!success)
    {
        ERROR_ReportWarning("Cannot create a mapping\n");
    }
    else
    {
        EXTERNAL_CreateMapping(
            iface,
            macKey,
            macKeySize,
            (char*) mapping,
            sizeof(AutoIPNE_NodeMapping));
    }

    mapping->next = data->deviceArray[deviceIndex].mappingsList;
    data->deviceArray[deviceIndex].mappingsList = mapping;
    data->numVirtualNodes++;

    if (data->debug)
    {
        // (Debug) following code prints the mapping information
        char addr1[64];
        Address tempAddress = virtualAddress;
        if (isIpv4Mode)
        {
            tempAddress.interfaceAddr.ipv4
                = ntohl(tempAddress.interfaceAddr.ipv4);
        }
        IO_ConvertIpAddressToString(&tempAddress, addr1);
        printf("\nVirtual Node Address %s", addr1);
        tempAddress = physicalAddress;
        if (isIpv4Mode)
        {
            tempAddress.interfaceAddr.ipv4
                = ntohl(tempAddress.interfaceAddr.ipv4);
        }
        IO_ConvertIpAddressToString(&tempAddress, addr1);
        printf("\nOperational Host Address %s", addr1);
        printf("\nMAC Address %s", mapping->macAddressString);
        printf("\n\n");
        // (Debug) End
    }

    if (isIpv4Mode)
    {
        iface->partition->rrInterface->
            RecordAddVirtualHost(ntohl(virtualAddress.interfaceAddr.ipv4));
    }
    else
    {
         iface->partition->rrInterface->
            RecordAddIPv6VirtualHost(virtualAddress);
    }

    AutoIPNERecompileCaptureFilter(data, deviceIndex);

    if (virtualNodePtr->partitionId
        != virtualNodePtr->partitionData->partitionId)
    {
        Message* msg = MESSAGE_Alloc(virtualNodePtr,
                EXTERNAL_LAYER,
                EXTERNAL_IPNE,
                EXTERNAL_MESSAGE_IPNE_SetExternalInterface);
        MESSAGE_SetInstanceId(msg, interfaceIndex);
        MESSAGE_PacketAlloc(virtualNodePtr, msg, sizeof(int), TRACE_IP);
        *(Int32*)MESSAGE_ReturnPacket(msg) = (Int32)mapping->isVirtualLan;

        EXTERNAL_MESSAGE_SendAnyNode(iface,
                                     virtualNodePtr,
                                     msg,
                                     0,
                                     EXTERNAL_SCHEDULE_SAFE);
    }
    else
    {
        virtualNodePtr->macData[interfaceIndex]->isIpneInterface = TRUE;
        virtualNodePtr->macData[interfaceIndex]->isVirtualLan
            = mapping->isVirtualLan;
    }
    if (OculaInterfaceEnabled())
    {
        char key[MAX_STRING_LENGTH];
        char value[MAX_STRING_LENGTH];

        sprintf(key, "/node/%d/exata/status", virtualNodePtr->nodeId);
        sprintf(value, "enabled");
        SetOculaProperty(
            virtualNodePtr->partitionData,
            key,
            value);

        sprintf(key, "/node/%d/exata/externalHostAddress", virtualNodePtr->nodeId);
        sprintf(value, "%s", inet_ntoa(* (struct in_addr *) &mapping->physicalAddress));
        SetOculaProperty(
            virtualNodePtr->partitionData,
            key,
            value);

        sprintf(key, "/node/%d/exata/ifIndex", virtualNodePtr->nodeId);
        sprintf(value, "%d", mapping->interfaceIndex);
        SetOculaProperty(
            virtualNodePtr->partitionData,
            key,
            value);

        sprintf(key, "/node/%d/exata/isDefaultExternalNode", virtualNodePtr->nodeId);
        sprintf(value, "1");
        SetOculaProperty(
            virtualNodePtr->partitionData,
            key,
            value);
    }
    if (iface->partition->firstNode->guiOption)
    {
        GUI_SetExternalNode(virtualNodePtr->nodeId,
                            0,
                            iface->partition->getGlobalTime());
    }
    return TRUE;
}

// /**
// API       :: AutoIPNE_RemoveVirtualNode
// PURPOSE   :: This function removes mapping of an virtual address with an
//              physical address
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + physicalAddress : Address : ipv4/ipv6 address of operational
//                         host
// + virtualAddress : Address : ipv4/ipv6 address of virtual node
// + localRouting : BOOL : local routing
// RETURN    :: BOOL : Whether mapping was successful removed or not
// **/
BOOL AutoIPNE_RemoveVirtualNode(
    EXTERNAL_Interface* iface,
    Address physicalAddress,
    Address virtualAddress,
    BOOL localRouting)
{
    Int32 nodeId, deviceIndex = -1, err;
    Node* node = NULL;
    AutoIPNEData* data = NULL;
    AutoIPNE_NodeMapping* mapping = NULL, *m = NULL, *p = NULL;
    Int32 valueSize = 0;
    BOOL isIpv4Mode = FALSE;
    Int32 keySize = 0;
    Int8* virtualAddressPtr = NULL;
    Int8* physicalAddressPtr = NULL;

    data = (AutoIPNEData *)iface->data;

    if (!data->isAutoIPNE)
    {
        ERROR_ReportWarning("Connection Manager does not work with Legacy IPNE");
        return FALSE;
    }

    if (data->debug)
    {
        char addr1[64];
        char addr2[64];
        IO_ConvertIpAddressToString(&physicalAddress, addr1);
        IO_ConvertIpAddressToString(&virtualAddress, addr2);
        printf("Deleting Virtual Node: %s %s %d\n",
            addr1, addr2, localRouting);
    }

    // Get the node pointer (from virtual address)
    nodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                iface->partition->firstNode, virtualAddress);
    if (nodeId == INVALID_ADDRESS)
    {
        if (data->debug)
        {
            char addr1[64];
            char buf[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&virtualAddress, addr1);
            sprintf(buf, "Invalid virtual node address: %s", addr1);
            ERROR_ReportWarning(buf);
        }
        return FALSE;
    }

    node = MAPPING_GetNodePtrFromHash(iface->partition->nodeIdHash, nodeId);
    if (node == NULL)
    {
        node = MAPPING_GetNodePtrFromHash(iface->partition->remoteNodeIdHash, nodeId);
        if (node == NULL)
        {
            if (data->debug)
            {
                char addr1[64];
                char buf[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(&virtualAddress, addr1);
                sprintf(buf, "Invalid virtual node address: %s or nodeId %d",
                    addr1, nodeId);
                ERROR_ReportWarning(buf);
            }
            return FALSE;
        }
    }

    virtualAddressPtr = (Int8*)&virtualAddress.interfaceAddr;
    physicalAddressPtr = (Int8*)&physicalAddress.interfaceAddr;
    if (virtualAddress.networkType == NETWORK_IPV4)
    {
        isIpv4Mode = TRUE;
        keySize = sizeof(NodeAddress);

        // Convert the address in network format
        virtualAddress.interfaceAddr.ipv4
            = htonl(virtualAddress.interfaceAddr.ipv4);
        physicalAddress.interfaceAddr.ipv4
            = htonl(physicalAddress.interfaceAddr.ipv4);
    }
    else
    {
        keySize = sizeof(in6_addr);
    }

    // Retrieve the node mapping for this virtual node 
    err = EXTERNAL_ResolveMapping(
            iface,
            virtualAddressPtr,
            keySize,
            (Int8 **) &mapping,
            &valueSize);

    if (err)
    {
        if (data->debug)
        {
            char addr1[64];
            char buf[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&virtualAddress, addr1);
            sprintf(buf, "Cannot resolve mapping for %s at %d",
                addr1, nodeId);
            ERROR_ReportWarning(buf);
        }
        return TRUE;
    }
    assert(valueSize == sizeof(AutoIPNE_NodeMapping));

    if (memcmp(physicalAddressPtr,
               &mapping->physicalAddress.interfaceAddr,
               keySize))
    {
        if (data->debug)
        {
            char addr1[64];
            char addr2[64];
            char buf[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&physicalAddress, addr1);
            IO_ConvertIpAddressToString(&mapping->physicalAddress, addr2);
            printf(buf, "Incorrect physical address in the mapping table %s %s",
                addr1, addr2);
            ERROR_ReportWarning(buf);
        }
        return TRUE;
    }

    deviceIndex = mapping->deviceIndex;

    // Remove the ipne flag
    if (node->partitionId != node->partitionData->partitionId)
    {
        Message* msg = MESSAGE_Alloc(node, EXTERNAL_LAYER, EXTERNAL_IPNE,
                            EXTERNAL_MESSAGE_IPNE_ResetExternalInterface);
        MESSAGE_SetInstanceId(msg, mapping->interfaceIndex);
        EXTERNAL_MESSAGE_SendAnyNode(
            iface, node, msg, 0, EXTERNAL_SCHEDULE_SAFE);
    }
    else
    {
        node->macData[mapping->interfaceIndex]->isIpneInterface = FALSE;
    }


    // Delete the mappings from hash table
    m = data->deviceArray[deviceIndex].mappingsList;

    //assert(m != NULL);
    if (m == NULL)
    {
        if (data->debug)
        {
            char addr1[64];
            char addr2[64];
            char buf[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&physicalAddress, addr1);
            IO_ConvertIpAddressToString(&virtualAddress, addr2);
            sprintf(buf, "Removing non-existent virtual node physical "
                "= %s virtual = %s",
                addr1, addr2);
            ERROR_ReportWarning(buf);
        }
        return TRUE;
    }

    if (m->next == NULL)
    {
        data->deviceArray[deviceIndex].mappingsList = NULL;
    }
    else
    {
        p = NULL;
        while (m != NULL)
        {
            if (!memcmp(&m->virtualAddress.interfaceAddr,
                        virtualAddressPtr,
                        keySize))
            {

                if (p != NULL)
                {
                    p->next = m->next;
                }
                else
                {
                    data->deviceArray[deviceIndex].mappingsList = m->next;
                }
                break;
            }
            p = m;
            m = m->next;
        }
    }

    MEM_free(m);
    m = NULL;

    /* Record removal of virtual host */
    if (isIpv4Mode)
    {
        iface->partition->rrInterface->
            RecordRemoveVirtualHost(ntohl(virtualAddress.interfaceAddr.ipv4));
    }
    else
    {
           iface->partition->rrInterface->
        RecordRemoveIPv6VirtualHost(virtualAddress);
    }

    data->numVirtualNodes --;

    // Recompile the pcap filter 
    AutoIPNERecompileCaptureFilter(data, deviceIndex);

    // Delete the mapping from device info list

    // Mapping for physical address
    if (mapping->ipneMode == AUTO_IPNE_MODE_NAT_ENABLED)
    {
        EXTERNAL_DeleteMapping(
                iface,
                (Int8*) &mapping->physicalAddress.interfaceAddr,
                keySize);
    }

    /* Mapping for macAddress
       Key in the mapping table is not the macAddress alone but also the
       corresponding device index. This is required to ensure that more than 1
       physical interface with the same MAC address can be stored without any
       collisions
    */

    char macKey[10];
    BOOL success;
    int macKeySize = mapping->macAddressSize + sizeof(deviceIndex);
    success = AutoIPNE_CreateMacKey(macKey,mapping->macAddress,deviceIndex);
    ERROR_Assert(success, "Cannot create a MAC key for deletion\n");

    // Mapping for macAddress
    EXTERNAL_DeleteMapping(
        iface,
        macKey,
        macKeySize);

    // Mapping for virtual address
    EXTERNAL_DeleteMapping(
            iface,
            (Int8*)&mapping->virtualAddress.interfaceAddr,
            keySize);

    if (iface->partition->firstNode->guiOption)
    {
        GUI_ResetExternalNode(node->nodeId, 0, iface->partition->getGlobalTime());
    }
    return TRUE;
}

void AutoIPNE_DisableInterface(
    Node *node,
    Address interfaceAddress)
{
    EXTERNAL_Interface *ipne = NULL;
    AutoIPNEData *ipneData = NULL;
    int i;

    // Get IPNE external interface
    ipne = EXTERNAL_GetInterfaceByName(
            &node->partitionData->interfaceList,
            "IPNE");

    if (ipne == NULL)
        return;

    ipneData = (AutoIPNEData*) ipne->data;

    if (!ipneData->isAutoIPNE)
    {
        return;
    }

    if (interfaceAddress.networkType == NETWORK_IPV4)
    {
        SetIPv4AddressInfo(
            &interfaceAddress,
            htonl(GetIPv4Address(interfaceAddress)));
    }

    for (i = 0; i < ipneData->numDevices; i++)
    {
        if (ipneData->deviceArray[i].disabled)
            continue;

        list<AutoIpneV4V6Address>::iterator it;
        it = ipneData->deviceArray[i].interfaceAddress->begin();
        for (; it != ipneData->deviceArray[i].interfaceAddress->end(); ++it)
        {
            if (it->address.networkType == NETWORK_IPV4
                && interfaceAddress.networkType == NETWORK_IPV4)
            {
                if (GetIPv4Address(it->address)
                    == GetIPv4Address(interfaceAddress))
                {
                    if (ipneData->deviceArray[i].pcapFrame)
                    {
                        pcap_close(ipneData->deviceArray[i].pcapFrame);
                    }
                    ipneData->deviceArray[i].disabled = TRUE;
                    break;
                }
            }
            if (it->address.networkType == NETWORK_IPV6
                && interfaceAddress.networkType == NETWORK_IPV6)
            {
                in6_addr add1 = GetIPv6Address(it->address);
                in6_addr add2 = GetIPv6Address(interfaceAddress);
                if (memcmp(&add1,
                           &add2,
                           sizeof(in6_addr))
                    == 0)
                {
                    if (ipneData->deviceArray[i].pcapFrame)
                    {
                        pcap_close(ipneData->deviceArray[i].pcapFrame);
                    }
                    ipneData->deviceArray[i].disabled = TRUE;
                    break;
                }
            }
        }
    }
}


// /**
// API       :: AutoIPNE_HandleIPStatisticsSendPacket
// PURPOSE   :: This function will compute statistics upon injecting info
//              back into the external source
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + bytes : int : number of bytes in this packet
// + receiveTime : clocktype : The time the packet was received.  This is
//                             the "now" value passed to
//                             HandleIPStatisticsReceive
// + now : clocktype : The current time
// RETURN    :: void
// **/
void AutoIPNE_HandleIPStatisticsSendPacket(
    EXTERNAL_Interface* iface,
    int bytes,
    clocktype receiveTime,
    clocktype now)
{
    AutoIPNEData* data;
    clocktype delay;
    clocktype D;

    assert(iface != NULL);
    data = (AutoIPNEData*) iface->data;
    assert(data != NULL);

    // Increment number of sent packets
    data->stats[AUTO_IPNE_STATS_ALL_OUT_PKT] ++;
    data->stats[AUTO_IPNE_STATS_ALL_OUT_BYTES] += bytes;

    // Compute delay for this packet
    delay = now - receiveTime;

    // If we have a delay time for a previous packet then update jitter
    if (data->lastSendIntervalDelay != EXTERNAL_MAX_TIME)
    {
        // Compute abs(delay difference)
        if (delay > data->lastSendIntervalDelay)
        {
            D = delay - data->lastSendIntervalDelay;
        }
        else
        {
            D = data->lastSendIntervalDelay - delay;
        }

        // Update jitter
        data->jitter += (D - data->jitter) / 16;
    }

    // Set last delay time, used for next packet
    data->lastSendIntervalDelay = delay;
}

// /**
// API       :: AutoIPNE_HandleIPStatisticsReceivePacket
// PURPOSE   :: This function will compute statistics upon receiving info
//              from the external source
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + bytes : int : Number of bytes in this packet
// + now : clocktype : The current time
// RETURN    :: void
// **/
void AutoIPNE_HandleIPStatisticsReceivePacket(
    EXTERNAL_Interface* iface,
    int bytes,
    clocktype now)
{
    AutoIPNEData* data;

    assert(iface != NULL);
    data = (AutoIPNEData*) iface->data;
    assert(data != NULL);

    // Increment number of received packets
    data->stats[AUTO_IPNE_STATS_ALL_IN_PKT] ++;
    data->stats[AUTO_IPNE_STATS_ALL_IN_BYTES] += bytes;

    // TODO: check out why this is #if 0
#if 0
    // Update average/maximum interval if this is not the first packet
    if (data->lastReceiveTime != EXTERNAL_MAX_TIME)
    {
        interval = now - data->lastReceiveTime;
        data->avgInterval += (interval - data->avgInterval) / 32;
        if (interval > data->maxInterval)
        {
            data->maxInterval = interval;
        }
    }
    data->lastReceiveTime = now;
#endif
}
#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
void  AutoIPNE_InitializeMiQualNodeMap(AutoIPNEData* data)
{
    MiQualnetNodeIdMapEntry* entry;
    NodeAddress addr;
    int i;
    UInt16 key;
    data->miQualNodeMap = new MiToQualnetNodeIdMap ();
     
    entry = (MiQualnetNodeIdMapEntry* )
            MEM_malloc(sizeof(MiQualnetNodeIdMapEntry));

    entry->ipAddress = 0xffffffd;
    entry->miNodeId = 0xffff;
    entry->qualNodeId = 0xfffd;
    entry->interfaceIndex = -1;
   
    key = entry->miNodeId;
    (*data->miQualNodeMap) [key] = entry;

}
void  AutoIPNE_InitializeQualnetMiNodeMap(AutoIPNEData* data)
{
    MiQualnetNodeIdMapEntry* entry;
    NodeAddress addr;
    int i;
    //UInt16 key;
    data->qualMiNodeMap = new QualnetToMiNodeIdMap ();
     
    entry = (MiQualnetNodeIdMapEntry* )
            MEM_malloc(sizeof(MiQualnetNodeIdMapEntry));

    entry->ipAddress = 0xffffffd;
    entry->miNodeId = 0xffff;
    entry->qualNodeId = 0xfffd;
    entry->interfaceIndex = -1;
   
    //key = entry->qualNodeId;
    std::pair<NodeId, int> key(entry->qualNodeId, entry->interfaceIndex);

    (*data->qualMiNodeMap) [key] = entry;

}
 MiQualnetNodeIdMapEntry* AutoIPNE_FindEntryForQualNodeId(AutoIPNEData* data, 
                                                          NodeId qualNodeId,
                                                          int interfaceIndex)
{
    QualnetToMiNodeIdMapIter entryIter;
    std::pair<NodeId,int> key(qualNodeId, interfaceIndex);
    entryIter = data->qualMiNodeMap->find (key);
    if (entryIter != data->qualMiNodeMap->end())
    {
       return (*entryIter).second;
    }
    return NULL;
}
 MiQualnetNodeIdMapEntry* AutoIPNE_FindEntryForMIId(AutoIPNEData* data, 
                                                    UInt16 miId)
{
    MiToQualnetNodeIdMapIter entryIter;
    entryIter = data->miQualNodeMap->find (miId);
    if (entryIter != data->miQualNodeMap->end())
    {
        return (*entryIter).second;
    }
    return NULL;

}
#endif

BOOL AutoIPNE_CreateMacKey(
    char key[],
    char* macAddress,
    int deviceIndex)
{
    int* deviceIndexPtr = &deviceIndex; 
    if (deviceIndex < 0)
    {
        ERROR_ReportWarning("No device to capture on\n");
        return FALSE;
    }
    else
    {
        memcpy(key,macAddress,ETHER_ADDR_LEN);
        memcpy(key+ETHER_ADDR_LEN,(char*)deviceIndexPtr, sizeof(deviceIndex));
        return TRUE;
    } 
}
