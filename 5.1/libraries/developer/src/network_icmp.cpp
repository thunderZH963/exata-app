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

/*
 * Name: icmp.cpp
 * Purpose: To simulate INTERNET CONTROL MESSAGE PROTOCOL (ICMP)
 *          following RFC 792, RFC 1256., RFC 1122, RFC 1812
 */

#include<stdio.h>
#include<string.h>
#include <stdlib.h>

#include "api.h"
#include "network_ip.h"
#include "network_icmp.h"
#include "transport_udp.h"
#include "transport_tcp.h"
#include "transport_tcp_hdr.h"
#include "external_socket.h"
#include "WallClock.h"

#ifdef ENTERPRISE_LIB
#include "network_mobileip.h"
#endif // ENTERPRISE_LIB

//#define DEBUG
//#define DEBUG_REDIR_NO_UPDATE
//#define DEBUG_REDIR_OWN_INFO
//#define ICMP_DEBUG
//#define DEBUG_ICMP_ERROR_MESSAGES

static void NetworkIcmpPrintRouterList(Node *node);



static void NetworkIcmpSetIcmpHeader(Node *node,
                                     Message *msg,
                                     Message *icmpPacket,
                                     unsigned short icmpType,
                                     unsigned short icmpCode,
                                     unsigned int seqOrGatOrPoin,
                                     unsigned short pointer);


static BOOL NetworkIcmpCheckIpAddressIsInSameSubnet(Node *node,
                                                    int interfaceIndex,
                                                    NodeAddress ipAddress);

static void NetworkIcmpFindFreeOrMinRowInRouterList(Node *node,
                                                    int *freeRow);

static void NetworkIcmpCheckAddressIsExistOrNot(Node *node,
                                                int *freeRow,
                                                NodeAddress routerAddress);

static void NetworkIcmpUpdateRouterList(Node *node,
                                        Message *msg,
                                        int interfaceIndex);

static void NetworkIcmpSendPacketToIp(Node *node,
                                      Message *icmpPacket,
                                      unsigned int ttl,
                                      unsigned int interfaceIndex,
                                      NodeAddress destinationAddress,
                                      TosType priority,
                                      NodeAddress *newSourceRoute,
                                      int sourceRoutelen,
                                      char *newRecordRoute,
                                      int recordRoutelen,
                                      char *newTimeStamp,
                                      int timeStamplen,
                                      NodeAddress immediateDestination);

static Message* NetworkIcmpCreateIcmpPacket(Node *node,
                                            unsigned short icmpType,
                                            unsigned short icmpCode,
                                            int interfaceIndex);

static void NetworkIcmpGenerateRouterDiscoveryMessage(Node *node,
                                              NodeAddress destinationAddress,
                                              unsigned short icmpType,
                                              unsigned short icmpCode,
                                              int interfaceIndex);

static void NetworkIcmpInitRouterListOfHost(Node *node);

static void NetworkIcmpRouterInterfaceInit(Node *node);

static void NetworkIcmpHostInterfaceInit(Node *node);

static void NetworkIcmpStatsInit(Node *node,
                                 const NodeInput *nodeInput);

static void NetworkIcmpParameterInit(Node *node,
                                     const NodeInput *nodeInput);
void NetworkIcmpPrintTraceXML(Node* node, Message* msg);

static void NetworkIcmpInitTrace(Node* node, const NodeInput* nodeInput);

// /**
// FUNCTION   :: NetworkIcmpPrintTraceXML
// LAYER      :: NETWORK
// PURPOSE    :: Print packet trace information in XML format
// PARAMETERS ::
// + node     : Node*    : Pointer to node
// + msg      : Message* : Pointer to packet to print headers from
// RETURN     ::  void   : NULL
// **/

void NetworkIcmpPrintTraceXML(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];
    IcmpHeader *icmpHeader = (IcmpHeader*) msg->packet;
    unsigned int nwords;
    unsigned short *tempbuf;

    IcmpData *icmpData = (IcmpData*) (msg->packet + sizeof(IcmpHeader));

    nwords = MESSAGE_ReturnActualPacketSize(msg);
    nwords = (nwords>>1);
    tempbuf = (unsigned short*)icmpHeader;


    sprintf(buf, "<icmp>");
    TRACE_WriteToBufferXML(node, buf);

    switch (icmpHeader->icmpMessageType)
    {
        case ICMP_ROUTER_ADVERTISEMENT:
        {
                sprintf(buf, "<icmp_router_advertisement>");
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "%hu %hu %hu %d",
                icmpHeader->icmpMessageType,
                icmpHeader->icmpCode,
                icmpHeader->icmpCheckSum & 0x0000, 10);

                TRACE_WriteToBufferXML(node, buf);

                char routeraddr[MAX_STRING_LENGTH];

                IO_ConvertIpAddressToString(
                    icmpData->RouterAdvertisementData.routerAddress,
                    routeraddr);
                sprintf(buf, "<routeradvertisementheader>%d %d %hu "
                                "%s %d </routeradvertisementheader>",
                icmpHeader->Option.RouterAdvertisementHeader.numAddr,
                icmpHeader->Option.RouterAdvertisementHeader.addrEntrySize,
                icmpHeader->Option.RouterAdvertisementHeader.lifeTime,
                routeraddr,
                icmpData->RouterAdvertisementData.preferenceLevel);
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "</icmp_router_advertisement>");
                TRACE_WriteToBufferXML(node, buf);

                break;
        }//End Router Advertisement
        case ICMP_ROUTER_SOLICITATION:
        {
                sprintf(buf, "<icmp_router_solicitation>");
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "%hu %hu %hu %d",
                icmpHeader->icmpMessageType,
                icmpHeader->icmpCode,
                icmpHeader->icmpCheckSum & 0x0000, 10);

                TRACE_WriteToBufferXML(node, buf);

                 char routeraddr[MAX_STRING_LENGTH];

                IO_ConvertIpAddressToString(
                    icmpData->RouterAdvertisementData.routerAddress,
                    routeraddr);
                sprintf(buf, "<routeradvertisementheader>%d %d %hu %s "
                                "%d </routeradvertisementheader>",
                icmpHeader->Option.RouterAdvertisementHeader.numAddr,
                icmpHeader->Option.RouterAdvertisementHeader.addrEntrySize,
                icmpHeader->Option.RouterAdvertisementHeader.lifeTime,
                routeraddr,
                icmpData->RouterAdvertisementData.preferenceLevel);
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "</icmp_router_solicitation>");
                TRACE_WriteToBufferXML(node, buf);
            break;

        } //End Router Solicitation
        case ICMP_TIME_EXCEEDED:
        {
                sprintf(buf, "<icmp_time_exceeded>");
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "%hu %hu %hu %d",
                icmpHeader->icmpMessageType,
                icmpHeader->icmpCode,
                icmpHeader->icmpCheckSum & 0x0000, 10);

                TRACE_WriteToBufferXML(node, buf);

                char routeraddr[MAX_STRING_LENGTH];

                IO_ConvertIpAddressToString(
                            icmpData->RouterAdvertisementData.routerAddress,
                            routeraddr);
                sprintf(buf, "<routeradvertisementheader>%d %d %hu %s "
                                "%d </routeradvertisementheader>",
                icmpHeader->Option.RouterAdvertisementHeader.numAddr,
                icmpHeader->Option.RouterAdvertisementHeader.addrEntrySize,
                icmpHeader->Option.RouterAdvertisementHeader.lifeTime,
                routeraddr,
                icmpData->RouterAdvertisementData.preferenceLevel);
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "</icmp_time_exceeded>");
                TRACE_WriteToBufferXML(node, buf);
            break;
        }//END TIME EXCEEDED
        case ICMP_DESTINATION_UNREACHABLE:
        {
                sprintf(buf, "<icmp_destination_unreachable>");
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "%hu %hu %hu %d",
                icmpHeader->icmpMessageType,
                icmpHeader->icmpCode,
                icmpHeader->icmpCheckSum & 0x0000, 10);

                TRACE_WriteToBufferXML(node, buf);

                char routeraddr[MAX_STRING_LENGTH];

                IO_ConvertIpAddressToString(
                    icmpData->RouterAdvertisementData.routerAddress,
                    routeraddr);
                sprintf(buf, "<routeradvertisementheader>%d %d %hu "
                                    "%s %d </routeradvertisementheader>",
                icmpHeader->Option.RouterAdvertisementHeader.numAddr,
                icmpHeader->Option.RouterAdvertisementHeader.addrEntrySize,
                icmpHeader->Option.RouterAdvertisementHeader.lifeTime,
                routeraddr,
                icmpData->RouterAdvertisementData.preferenceLevel);
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "</icmp_destination_unreachable>");
                TRACE_WriteToBufferXML(node, buf);
            break;
        }//END DESTINATION UNREACHABLE
        case ICMP_ECHO_REPLY:
        {
                sprintf(buf, "<icmp_echo_reply>");
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "%hu %hu %hu %d",
                icmpHeader->icmpMessageType,
                icmpHeader->icmpCode,
                icmpHeader->icmpCheckSum & 0x0000, 10);

                TRACE_WriteToBufferXML(node, buf);

                char routeraddr[MAX_STRING_LENGTH];

                IO_ConvertIpAddressToString(
                    icmpData->RouterAdvertisementData.routerAddress,
                    routeraddr);
                sprintf(buf, "<routeradvertisementheader>%d %d %hu "
                                "%s %d </routeradvertisementheader>",
                icmpHeader->Option.RouterAdvertisementHeader.numAddr,
                icmpHeader->Option.RouterAdvertisementHeader.addrEntrySize,
                icmpHeader->Option.RouterAdvertisementHeader.lifeTime,
                routeraddr,
                icmpData->RouterAdvertisementData.preferenceLevel);
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "</icmp_echo_reply>");
                TRACE_WriteToBufferXML(node, buf);
            break;
        }//END ECHO REPLY
    }
    sprintf(buf, "</icmp>");
    TRACE_WriteToBufferXML(node, buf);
}


// /**
// FUNCTION   :: NetworkIcmpInitTrace
// LAYER      :: NETWORK
// PURPOSE    :: IP initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
// **/

static
void NetworkIcmpInitTrace(Node* node, const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    BOOL traceAll = TRACE_IsTraceAll(node);
    BOOL trace = FALSE;
    static BOOL writeMap = TRUE;

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TRACE-ICMP",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            trace = TRUE;
        }
        else if (strcmp(buf, "NO") == 0)
        {
            trace = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "TRACE-ICMP should be either \"YES\" or \"NO\".\n");
        }
    }
    else
    {
        if (traceAll || node->traceData->layer[TRACE_NETWORK_LAYER])
        {
            trace = TRUE;
        }
    }

    if (trace)
    {
            TRACE_EnableTraceXML(node, TRACE_ICMP,
                "ICMP", NetworkIcmpPrintTraceXML, writeMap);
    }
    else
    {
            TRACE_DisableTraceXML(node, TRACE_ICMP,
                "ICMP", writeMap);
    }
    writeMap = FALSE;
}

/*
 * FUNCTION:    NetworkIcmpInit()
 * PURPOSE:     This function is called from  NetworkIpInit(..) function to
 *              initialize the Icmp module.
 * RETURN:      NULL
 * ASSUMPTIONS: None
 * PARAMETERS:  node,           node which is allocating message
 *              nodeInput,      Structure containing contents of input file.
 */

void NetworkIcmpInit(Node *node,
                     const NodeInput *nodeInput)
{
    BOOL retVal;
    char buf[MAX_STRING_LENGTH];

    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;

    NetworkDataIcmp *icmp =
                     (NetworkDataIcmp*)
                     MEM_malloc(sizeof(NetworkDataIcmp));

    ipLayer->icmpStruct = icmp;
    ipLayer->isIcmpEnable = TRUE;

    RANDOM_SetSeed(icmp->seed,
                   node->globalSeed,
                   node->nodeId,
                   NETWORK_PROTOCOL_ICMP);

    ERROR_Assert(ICMP_MAX_ERROR_MESSAGE_SIZE >= 56,
                  "ICMP_ERROR_MESSAGE_SIZE should be atleast 56 byte");

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-NETWORK-UNREACHABLE-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->networkUnreachableEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->networkUnreachableEnable = TRUE;
    }
    else
    {
        icmp->networkUnreachableEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-NETWORK-UNREACHABLE: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

        IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-HOST-UNREACHABLE-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->hostUnreachableEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->hostUnreachableEnable = TRUE;
    }
    else
    {
        icmp->hostUnreachableEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-HOST-UNREACHABLE: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-PROTOCOL-UNREACHABLE-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->protocolUnreachableEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->protocolUnreachableEnable = TRUE;
    }
    else
    {
        icmp->protocolUnreachableEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-PROTOCOL-UNREACHABLE: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-PORT-UNREACHABLE-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->portUnreachableEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->portUnreachableEnable = TRUE;
    }
    else
    {
        icmp->portUnreachableEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-PORT-UNREACHABLE: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-FRAGMENTATION-NEEDED-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->fragmentationNeededEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->fragmentationNeededEnable = TRUE;
    }
    else
    {
        icmp->fragmentationNeededEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-FRAGMENTATION-NEEDED: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-SOURCE-ROUTE-FAILED-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->sourceRouteFailedEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->sourceRouteFailedEnable = TRUE;
    }
    else
    {
        icmp->sourceRouteFailedEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-SOURCE-ROUTE-FAILED: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-SOURCE-QUENCE-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->sourceQuenchEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->sourceQuenchEnable = TRUE;
    }
    else
    {
        icmp->sourceQuenchEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-SOURCE-QUENCH: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-TTL-EXCEEDED-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->TTLExceededEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->TTLExceededEnable = TRUE;
    }
    else
    {
        icmp->TTLExceededEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-TTL_EXCEEDED: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-FRAGMENTS-REASSEMBLY-TIMEOUT-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->fragmentsReassemblyTimeoutEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->fragmentsReassemblyTimeoutEnable = TRUE;
    }
    else
    {
        icmp->fragmentsReassemblyTimeoutEnable = TRUE;
        ERROR_ReportWarning(
         "ICMP-FRAGMENTS-REASSEMBLY-TIMEOUT: Unknown value in configuration"
         "file.Taking default value as ""YES""\n");
    }

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-PARAMETER-PROBLEM-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->parameterProblemEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->parameterProblemEnable = TRUE;
    }
    else
    {
        icmp->parameterProblemEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-PARAMETER-PROBLEM: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-SECURITY-FAILURE-ENABLED",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->securityFailureEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->securityFailureEnable = TRUE;
    }
    else
    {
        icmp->securityFailureEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-SECURITY-FAILURE: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

    IO_ReadString(
           node->nodeId,
           ANY_DEST,
           nodeInput,
           "ICMP-REDIRECT-ENABLE",
           &retVal,
           buf);

    if (retVal && !strcmp (buf, "NO"))
    {
        icmp->redirectEnable = FALSE;
    }
    else if (!retVal || !strcmp (buf, "YES"))
    {
        icmp->redirectEnable = TRUE;
    }
    else
    {
        icmp->redirectEnable = TRUE;
        ERROR_ReportWarning(
            "ICMP-REDIRECT: Unknown value in configuration"
            "file.Taking default value as ""YES""\n");
    }

    // Initialize all the state variables for statistics
    NetworkIcmpStatsInit(node, nodeInput);
    NetworkIcmpParameterInit(node, nodeInput);
    NetworkIcmpInitTrace(node, nodeInput);

    icmp->redirectCacheInfo = NULL;

    ListInit(node, &icmp->routerDiscoveryFunctionList);
    ListInit(node, &icmp->routerTimeoutFunctionList);

    // Determine whether node is host or router from configuration file
    retVal = FALSE;
    icmp->router = FALSE;

    IO_ReadBool(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "ICMP-ROUTER",
            &retVal,
            &icmp->router);

    if (icmp->router == FALSE)
    {
        // Initialize data structures for a host
        NetworkIcmpHostInterfaceInit(node);
    }
    else
    {
        // Intialize data structures for a Router
        NetworkIcmpRouterInterfaceInit(node);
    }
}


/*
 * FUNCTION:    NetworkIcmpStatsInit()
 * PURPOSE:     This function is called from  IcmpInit() function to
 *              initialize all the statistics variables and flags for ICMP.
 * RETURN:      NULL
 * ASSUMPTION:  None
 * PARAMETERS:  node,          node which is runing ICMP
 *              nodeInput,     Structure containing contents of input file.
 */

static void NetworkIcmpStatsInit(Node *node,
                                 const NodeInput *nodeInput)
{
    BOOL retVal;
    char buf[MAX_STRING_LENGTH];
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    IO_ReadString(node->nodeId,
                     ANY_DEST,
                     nodeInput,
                     "ICMP-STATISTICS",
                     &retVal,
                     buf);

    if (!retVal || (strcmp(buf, "NO") == 0))
    {
        icmp->collectStatistics = FALSE;
    }
    else if (strcmp(buf, "YES") == 0)
    {
        icmp->collectStatistics = TRUE;
    }
    else
    {
        icmp->collectStatistics = FALSE;
        ERROR_ReportWarning(
            "ICMP-STATISTICS: Unknown value in configuration"
            "file.Taking default value as ""NO""\n");
    }

     IO_ReadString(node->nodeId,
                     ANY_DEST,
                     nodeInput,
                     "ICMP-ERROR-STATISTICS",
                     &retVal,
                     buf);

    if (!retVal || (strcmp(buf, "NO") == 0))
    {
        icmp->collectErrorStatistics = FALSE;
    }
    else if (strcmp(buf, "YES") == 0)
    {
        icmp->collectErrorStatistics = TRUE;
    }
    else
    {
        icmp->collectErrorStatistics = FALSE;
        ERROR_ReportWarning(
            "ICMP-ERROR-STATISTICS: Unknown value in configuration"
            "file.Taking default value as ""NO""\n");
    }


    memset(&icmp->icmpStat, 0, sizeof(IcmpStat));
    memset(&icmp->icmpErrorStat, 0, sizeof(IcmpErrorStat));
}


/*
 * FUNCTION:    NetworkIcmpParameterInit()
 * PURPOSE:     This function is called from  IcmpInit() function to
 *              initialize all the configuraiton parameters of ICMP.
 * RETURN:      NULL
 * ASSUMPTION:  None
 * PARAMETERS:  node,          node which is runing ICMP
 *              nodeInput,     Structure containing contents of input file.
 */

static void NetworkIcmpParameterInit(Node *node,
                                     const NodeInput *nodeInput)
{
    BOOL retVal;
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;
    clocktype timeVal;
    int intVal;
    char buf[MAX_STRING_LENGTH];

    IO_ReadTime(node->nodeId,
                ANY_DEST,
                nodeInput,
                "ICMP-ROUTER-ADVERTISEMENT-MIN-INTERVAL",
                &retVal,
                &timeVal);

    if (retVal)
    {
        icmp->parameter.minAdverInterval = timeVal;
    }
    else
    {
        icmp->parameter.minAdverInterval = (clocktype) ICMP_AD_MIN_INTERVAL;
    }

    IO_ReadTime(node->nodeId,
                ANY_DEST,
                nodeInput,
                "ICMP-ROUTER-ADVERTISEMENT-MAX-INTERVAL",
                &retVal,
                &timeVal);

    if (retVal)
    {
        if (timeVal >= icmp->parameter.minAdverInterval)
        {
            icmp->parameter.maxAdverInterval = timeVal;
        }
        else
        {
            ERROR_ReportError("ICMP-ROUTER-ADVERTISEMENT-MAX-INTERVAL "
                "should be larger than "
                "ICMP-ROUTER-ADVERTISEMENT-MIN-INTERVAL");
        }
    }
    else
    {
        icmp->parameter.maxAdverInterval = ICMP_AD_MAX_INTERVAL;
    }

    IO_ReadTime(node->nodeId,
                ANY_DEST,
                nodeInput,
                "ICMP-ROUTER-ADVERTISEMENT-LIFE-TIME",
                &retVal,
                &timeVal);

    if (retVal)
    {
        if (timeVal < 1 * SECOND)
        {
            ERROR_ReportError("ICMP-ROUTER-ADVERTISEMENT-LIFE-TIME "
                "must be larger than 1 second");
        }
        else if (timeVal <= icmp->parameter.maxAdverInterval)
        {
            ERROR_ReportError("ICMP-ROUTER-ADVERTISEMENT-LIFE-TIME "
                "should be larger than "
                "ICMP-ROUTER-ADVERTISEMENT-MAX-INTERVAL");
        }
        else
        {
            icmp->parameter.adverLifeTime = timeVal;
        }
    }
    else
    {
        icmp->parameter.adverLifeTime = ICMP_AD_LIFE_TIME;
    }

    if (icmp->redirectEnable)
    {
        IO_ReadTime(node->nodeId,
                    ANY_DEST,
                    nodeInput,
                    "ICMP-REDIRECT-RETRY-TIME",
                    &retVal,
                    &timeVal);

        if (retVal)
        {
                icmp->parameter.redirectRertyTimeout = timeVal;
        }
        else
        {
            icmp->parameter.redirectRertyTimeout = ICMP_REDIRECT_CACHE_TIME;
        }
    }
    // Read how many router solicitations that a host can
    // send after startup.
    IO_ReadInt(node->nodeId,
               ANY_DEST,
               nodeInput,
               "ICMP-MAX-NUM-SOLICITATION",
               &retVal,
               &intVal);

    if (retVal)
    {
        if (intVal >= 0)
        {
            icmp->parameter.maxNumSolicits = intVal;
        }
        else
        {
            ERROR_ReportError("ICMP-MAX-NUM-SOLICITATION should be"
                " larger or equal to 0");
        }
    }
    else
    {
        icmp->parameter.maxNumSolicits = ICMP_MAX_SOLICITATIONS;
    }

    //Determines whether a redirect message should override an existing entry
    //in the forwarding table for a non-static route.  RFC 1812 allows
    //for this to be optionally defined.  By default, this is enabled.
    IO_ReadString(node->nodeId,
                     ANY_DEST,
                     nodeInput,
                     "ICMP-REDIRECT-OVERRIDE-ROUTING",
                     &retVal,
                     buf);

    if ((retVal == FALSE) || (strcmp(buf, "YES") == 0))
    {
        icmp->parameter.redirectOverrideRoutingProtocol = TRUE;
    }
    else if (strcmp(buf, "NO") == 0)
    {
        icmp->parameter.redirectOverrideRoutingProtocol = FALSE;
    }
    else
    {
        ERROR_ReportError("ICMP-REDIRECT-OVERRIDE-ROUTING should be"
                " either YES or NO");
    }

#ifdef DEBUG
    {
        char clockStr[MAX_STRING_LENGTH];

        printf("ICMP configuration parameters of Node%d\n", node->nodeId);

        ctoa(icmp->parameter.minAdverInterval, clockStr);
        printf("    Minimal Advertisement Interval = %s\n", clockStr);

        ctoa(icmp->parameter.maxAdverInterval, clockStr);
        printf("    Maximal Advertisement Interval = %s\n", clockStr);

        ctoa(icmp->parameter.adverLifeTime, clockStr);
        printf("    Lifetime of Avertisement = %s\n", clockStr);

        printf("    Maximum # of Solicitations = %d\n",
                icmp->parameter.maxNumSolicits);

        printf("    ICMP redirects will override routing protocols = %d\n",
            icmp->parameter.redirectOverrideRoutingProtocol);
    }
#endif // DEBUG
}



/*
 * FUNCTION:    NetworkIcmpHostInterfaceInit()
 * PURPOSE:     This function is called from  IcmpInit() function to
 *              intialize data structures for each multicast interface
 *              of a Host.
 * RETURN:      NULL
 * ASSUMPTION:  None
 * PARAMETERS:  node,       node which is allocating message
 */

static void NetworkIcmpHostInterfaceInit(Node *node)
{
    int index;
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;
    NetworkProtocolType networkProtocol =
                         NetworkIpGetNetworkProtocolType(node, node->nodeId);
    if (networkProtocol != GSM_LAYER3)
    {
        for (index = 0; index < node->numberInterfaces; index++)
        {
            HostInterfaceStructure *hostInterfaceStructure =
                (HostInterfaceStructure*)
                MEM_malloc (sizeof(HostInterfaceStructure));

            icmp->interfaceStruct[index] = hostInterfaceStructure;
            hostInterfaceStructure->performRouterDiscovery = TRUE;
            hostInterfaceStructure->solicitationNumber = 0;

            hostInterfaceStructure->alreadyGotRouterSolicitationMessage =
                                                                       FALSE;

        } //End for

        NetworkIcmpInitRouterListOfHost(node);

        // Start to generating Router Solicitation message randomly from
        // each multicast interface.

        for (index = 0; index < node->numberInterfaces; index++)
        {
            HostInterfaceStructure *hostInterfaceStructure =
                       (HostInterfaceStructure*)icmp->interfaceStruct[index];

            if (hostInterfaceStructure->performRouterDiscovery == TRUE)
            {

                Message *routerSolicitationMsg;
                clocktype delayForSolicitation;

                delayForSolicitation = (clocktype)
                    (RANDOM_nrand(icmp->seed)
                     % ICMP_MAX_SOLICITATION_DELAY + 1);

                routerSolicitationMsg = MESSAGE_Alloc(
                                         node,
                                         NETWORK_LAYER,
                                         NETWORK_PROTOCOL_ICMP,
                                         MSG_NETWORK_IcmpRouterSolicitation);

                MESSAGE_InfoAlloc(node, routerSolicitationMsg, sizeof(int));
                *((int *)MESSAGE_ReturnInfo(routerSolicitationMsg)) = index;

                MESSAGE_Send(node, routerSolicitationMsg,
                                                       delayForSolicitation);
            }
        } //End for
    }
}


/*
 * FUNCTION:    NetworkIcmpRouterInterfaceInit()
 * PURPOSE:     This function is called from  IcmpInit() function to
 *              intialize data structures for each multicast interface
 *              of a Router.
 * RETURN:      NULL
 * ASSUMPTIONS: None
 * PARAMETERS:  node,     node which is allocating message
 */

static void NetworkIcmpRouterInterfaceInit(Node *node)
{
    int index;
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    for (index = 0; index < node->numberInterfaces; index++)
    {
        RouterInterfaceStructure *routerInterfaceStructure =
                      (RouterInterfaceStructure*)
                      MEM_malloc(sizeof(RouterInterfaceStructure));

        icmp->interfaceStruct[index] = routerInterfaceStructure;

        // Determine if the address of this interface is to be advertised.
        routerInterfaceStructure->advertise = TRUE;

        routerInterfaceStructure->solicitationFlag = FALSE;
        routerInterfaceStructure->advertiseFlag = FALSE;
        routerInterfaceStructure->advertisementNumber = 0;
        routerInterfaceStructure->preferenceLevel = ICMP_AD_PREFERNCE_LEVEL;

    } //End for

    // Start to generating Router Advertisement message randomly from
    // each multicast interface.

    for (index = 0; index < node->numberInterfaces; index++)
    {
        RouterInterfaceStructure *routerInterfaceStructure =
                                                (RouterInterfaceStructure*)
                                                icmp->interfaceStruct[index];

        if (routerInterfaceStructure->advertise == TRUE)
        {
            Message *routerAdMsg;
            clocktype delayForAdvertisement;

#ifdef DEBUG
            NodeAddress interfaceIpAddress = NetworkIpGetInterfaceAddress(
                                                                      node,
                                                                      index);
#endif // DEBUG

            // Uniform between minAdverInterval and maxAdverInterval
            delayForAdvertisement = (clocktype)
                ((RANDOM_nrand(icmp->seed)) %
                (clocktype) (icmp->parameter.maxAdverInterval -
                icmp->parameter.minAdverInterval + 1) +
                icmp->parameter.minAdverInterval);

            // First few advertisement must not be longer than
            // ICMP_MAX_INITIAL_ADVERT_INTERVAL
            if (delayForAdvertisement > ICMP_MAX_INITIAL_ADVERT_INTERVAL)
            {
                delayForAdvertisement = ICMP_MAX_INITIAL_ADVERT_INTERVAL;
            }

            routerAdMsg = MESSAGE_Alloc(node,
                                        NETWORK_LAYER,
                                        NETWORK_PROTOCOL_ICMP,
                                        MSG_NETWORK_IcmpRouterAdvertisement);

            MESSAGE_InfoAlloc(node, routerAdMsg, sizeof(int));
            *((int *)MESSAGE_ReturnInfo(routerAdMsg)) = index;
            routerInterfaceStructure->advertiseFlag = TRUE;

            MESSAGE_Send(node, routerAdMsg, delayForAdvertisement);

        } //End if

    } //End for
}


/*
 * FUNCTION:    NetworkIcmpInitRouterListOfHost()
 * PURPOSE:     This function is called from  IcmpHostInterfaceInit()
 *              function  to intialize row of RouterList Table of a Host.
 * RETURN:      NULL
 * ASSUMPTIONS: None
 * PARAMETERS:  node,        node which is allocating message
 */

static void NetworkIcmpInitRouterListOfHost(Node *node)
{
    int index;
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    for (index = 0; index < ICMP_DEFAULT_HOST_ROUTERLIST_SIZE; index++)
    {
        icmp->hostRouterList[index].systemConfiguration = FALSE;
        icmp->hostRouterList[index].validRow = FALSE;
        icmp->hostRouterList[index].count = 0;
        icmp->hostRouterList[index].interfaceIndex = 0;
        icmp->hostRouterList[index].routerAddr = 0;
        icmp->hostRouterList[index].preferenceLevel = 0;
        icmp->hostRouterList[index].timeToLife = 0;

    } //End for
}




/*
 * FUNCTION:   NetworkIcmpGenerateRouterDiscoveryMessage()
 * PURPOSE:    This function will be called from the function
 *             HandleProtocolEvent(...) require to generate Router
 *             Advertisement or Router Solicitation message.
 * RETURN:     NULL
 * ASSUMPTION: None
 * PARAMETERS: node,               node which is allocating message
 *             destinationAddress, destination address of this message.
 *             icmpType,           type of ICMP Router Discovery message
 *             icmpCode,           code of ICMP Router Discovery message
 *             interfaceIndex,     to which interface this message will be
 *                                 multicast or broadcast
 */

static void NetworkIcmpGenerateRouterDiscoveryMessage(Node *node,
                                              NodeAddress destinationAddress,
                                              unsigned short icmpType,
                                              unsigned short icmpCode,
                                              int interfaceIndex)

{
    Message *icmpPacket = NULL;

    unsigned int ttl = 0;
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;
    TosType priority = 0;

    switch (icmpType)
    {
        case ICMP_ROUTER_ADVERTISEMENT:
        {
            icmpPacket = NetworkIcmpCreateIcmpPacket(node,
                                                     icmpType,
                                                     icmpCode,
                                                     interfaceIndex);

            NetworkIcmpSetIcmpHeader(node,
                                     NULL,
                                     icmpPacket,
                                     icmpType,
                                     icmpCode,
                                     0,
                                     0);

#ifdef ENTERPRISE_LIB
            // for mobile IP agent adv. message sent with TTL =1
            if (ipLayer->mobileIpStruct)
            {
                NetworkDataMobileIp* mobileIp = (NetworkDataMobileIp*)
                                                 ipLayer->mobileIpStruct;

                if (mobileIp->agent == BothAgent ||
                    mobileIp->agent == HomeAgent ||
                    mobileIp->agent == ForeignAgent)
                {
                    ttl = 1;
                }
            }
#endif // ENTERPRISE_LIB

            #ifdef DEBUG
            {
                char clockStr[100];
                ctoa(node->getNodeTime(), clockStr);

                printf("    sending ROUTER ADVERTISEMENT to %u "
                       "on interface %u at time %s\n",
                       destinationAddress, interfaceIndex, clockStr);
            }
            #endif
            priority = ICMP_REPLY_MSG_PRIO_DEFAULT;
            (icmp->icmpStat.icmpAdvertisementGenerate)++;

            break;

        } //End Router Advertisement

        case ICMP_ROUTER_SOLICITATION:
        {
            icmpPacket = NetworkIcmpCreateIcmpPacket(node,
                                                     icmpType,
                                                     icmpCode,
                                                     interfaceIndex);

            NetworkIcmpSetIcmpHeader(node,
                                     NULL,
                                     icmpPacket,
                                     icmpType,
                                     icmpCode,
                                     0,
                                     0);

#ifdef ENTERPRISE_LIB
            // for mobile IP agent adv. message sent with TTL =1
            if (ipLayer->mobileIpStruct)
            {
                NetworkDataMobileIp* mobileIp = (NetworkDataMobileIp*)
                                                ipLayer->mobileIpStruct;
                if (mobileIp->agent == MobileNode)
                {
                    ttl = 1;
                }
            }
#endif // ENTERPRISE_LIB

            #ifdef DEBUG
            {
                char clockStr[100];
                ctoa(node->getNodeTime(), clockStr);

                printf("    sending ROUTER SOLICITATION to %u "
                       "on interface %u at time %s\n",
                       destinationAddress, interfaceIndex, clockStr);
            }
            #endif

            priority = ICMP_REQUEST_MSG_PRIO_DEFAULT;
            (icmp->icmpStat.icmpSolicitationGenerate)++;
            break;

        } //End Router Solicitation

        default:
        {
            char str[MAX_STRING_LENGTH];
            sprintf(str,"\n Unknown ICMP Router Discovery Type");
            ERROR_Assert(FALSE, str);
        }

    } //End switch (icmpType)

    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, icmpPacket, TRACE_NETWORK_LAYER,
              PACKET_OUT, &acnData);

    NetworkIcmpSendPacketToIp(node, icmpPacket, 0, interfaceIndex,
                             destinationAddress, priority, NULL, 0, NULL, 0,
                             NULL, 0, 0);
}



/*
 * FUNCTION:   NetworkIcmpHandleProtocolPacket()
 * PURPOSE:    This is a interface function to receive all type of ICMP
 *             messages.This function will be called from
 *             ProcessPacketForMeFromMac() in nwip.pc when it get a message
 *             with ICMP protocol.This function calculate all statistics
 *             of ICMP module.If it receive any request message/
 *             solicitation message,then call IcmpGenerateIcmpReplyMessage
 *             / IcmpGenerateRouterDiscoveryMessage() to generate reply
 *             message or Router Advertisement message.
 * RETURN:     NULL
 * ASSUMPTION: None
 * PARAMETERS: node,               node which is allocating message
 *             msg,                message with ICMP protocol
 *             sourceAddress,      source address of this message
 *             destinationAddress, Ip address in which interface this message
 *                                 has been come.
 *             interfaceIndex,     incoming interface
 */

void NetworkIcmpHandleProtocolPacket(Node * node,
                                     Message *msg,
                                     NodeAddress sourceAddress,
                                     NodeAddress destinationAddress,
                                     int interfaceIndex)
{
    IcmpHeader *icmpHeader = (IcmpHeader*) msg->packet;
    unsigned char ipProtocolNumber;
    char err[MAX_STRING_LENGTH];
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    #ifdef DEBUG
    {
        char clockStr[100];
        ctoa(node->getNodeTime(), clockStr);

        printf("Node %u received packet at time %s\n",
                                                    node->nodeId, clockStr);
    }
    #endif

    switch (icmpHeader->icmpMessageType)
    {
        case ICMP_ROUTER_ADVERTISEMENT:
        {
            #ifdef DEBUG
            {
                printf("    got ROUTER ADVERTISEMENT\n");
            }
            #endif

            if (icmp->router == TRUE)
            {
                // Router silently discards it.

                #ifdef DEBUG
                {
                    printf("    is a router, so discard\n");
                }
                #endif

            } //End if

            else if (icmp->router == FALSE)
            {
                HostInterfaceStructure *hostInterfaceStructure =
                               (HostInterfaceStructure*)
                               icmp->interfaceStruct[interfaceIndex];

                hostInterfaceStructure->
                                 alreadyGotRouterSolicitationMessage = TRUE;

                #ifdef DEBUG
                {
                    printf("    not a router\n");
                }
                #endif

                NetworkIcmpUpdateRouterList(node, msg, interfaceIndex);

                NetworkIcmpCallRouterDiscoveryFunction(node, msg,
                      sourceAddress, destinationAddress, interfaceIndex);

                (icmp->icmpStat.icmpAdvertisementReceive)++;
            } //End else if

            break;
        } //End Router Advertisement

        case ICMP_ROUTER_SOLICITATION:
        {
            #ifdef DEBUG
            {
                printf("    got ROUTER SOLICITATION\n");
            }
            #endif

            if (icmp->router == TRUE)
            {
                #ifdef DEBUG
                {
                    printf("    is a router\n");
                }
                #endif

                // Unicast advertisements for solicitation with no delay.
                if (sourceAddress != 0)
                {
                    NetworkIcmpGenerateRouterDiscoveryMessage(node,
                                               sourceAddress,
                                               ICMP_ROUTER_ADVERTISEMENT,
                                               0,
                                               interfaceIndex);
                }
                // Only occurs when host doesn't yet know it's ip address.
                // This never occurs in QualNet.  But if it does,
                // send after some delay.
                else
                {
                    clocktype delayForAdvertisement;

                    RouterInterfaceStructure *routerInterfaceStructure =
                                      (RouterInterfaceStructure*)
                                      icmp->interfaceStruct[interfaceIndex];

                    Message *routerAdMsg = MESSAGE_Alloc(node,
                                    NETWORK_LAYER,
                                    NETWORK_PROTOCOL_ICMP,
                                    MSG_NETWORK_IcmpRouterAdvertisement);

#ifdef DEBUG
                    NodeAddress interfaceIpAddress =
                         NetworkIpGetInterfaceAddress(node, interfaceIndex);
#endif

                    delayForAdvertisement = (clocktype)
                                            (RANDOM_nrand(icmp->seed))
                                            % ICMP_MAX_RESPONSE_DELAY + 1;

                    MESSAGE_InfoAlloc(node, routerAdMsg, sizeof(int));

                    *((int *)MESSAGE_ReturnInfo(routerAdMsg)) =
                                                              interfaceIndex;

                    routerInterfaceStructure->solicitationFlag = TRUE;

                    MESSAGE_Send(node,
                                  routerAdMsg,
                                  delayForAdvertisement);
                }//else//

                (icmp->icmpStat.icmpSolicitationReceive)++;

            } //End if

            else if (icmp->router == FALSE)
            {
                #ifdef DEBUG
                {
                    printf("    is not router, so discard\n");
                }
                #endif

                //  host silently discards it
            } //End else if

            break;
        } //End Router Solicitation

        case ICMP_REDIRECT:
        {
            #ifdef DEBUG
            {
                printf("    got Redirect Message\n");
            }
            #endif

//this ifndef statement exists for testing purposes, it should always be
//disabled for proper functionality.
#ifndef DEBUG_REDIR_NO_UPDATE
            NetworkIcmpHandleRedirect(node, msg, sourceAddress,
                                                             interfaceIndex);
#endif
            icmp->icmpErrorStat.icmpRedirectReceive++;
#ifdef DEBUG
            printf("icmpRedirectReceive = %u\n",
                                    icmp->icmpErrorStat.icmpRedirectReceive);
#endif

            break;
        } //End Redirect Message

        case ICMP_ECHO:
        {
            (icmp->icmpStat.icmpEchoReceived)++;
            NetworkIcmpHandleEcho(node,
                                  msg,
                                  sourceAddress,
                                  interfaceIndex);
            break;
        }

        case ICMP_ECHO_REPLY:
        {
            sprintf(err, "node %d should not receive Echo Reply"
                         "message   \n", node->nodeId);
            ERROR_ReportWarning(err);
            break;
        }

        case ICMP_TIME_STAMP_REPLY:
        {
            sprintf(err, "node %d should not receive TimeStamp"
                         "Reply message   \n", node->nodeId);
            ERROR_ReportWarning(err);
            break;
        }

        case ICMP_TRACEROUTE:
        {
            sprintf(err, "node %d should not receive TraceRoute"
                         " message", node->nodeId);
            ERROR_ReportWarning(err);
            break;
        }

        case ICMP_TIME_STAMP:
        {
            clocktype now;
            int time;

            (icmp->icmpStat.icmpTimestampReceived)++;

            char *origPacket = MESSAGE_ReturnPacket(msg);
            char *receiveTime = origPacket;
            receiveTime = receiveTime + 12;
            now = WallClock::getTrueRealTime();
            time = (int)now / MILLI_SECOND;
            memcpy(receiveTime, &time, 4);

           //generate Timestamp Reply message.
            NetworkIcmpHandleTimestamp(node,
                                       msg,
                                       sourceAddress,
                                       interfaceIndex);
            break;
        }


        case ICMP_TIME_EXCEEDED:
        {
            if (icmpHeader->icmpCode == ICMP_TTL_EXPIRED_IN_TRANSIT)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got ttl expired message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpTTLExceededRecd)++;
            }
            else if (icmpHeader->icmpCode ==
                                  ICMP_FRAGMENT_REASSEMBLY_TIME_EXCEEDED)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got reassembly timeout message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpFragmReassemblyRecd)++;
            }
            MESSAGE_RemoveHeader(node,
                                 msg,
                                 sizeof(IcmpHeader),
                                 TRACE_ICMP);

            IpHeaderType *ipHeader = (IpHeaderType*)MESSAGE_ReturnPacket
                                     (msg);
            ipProtocolNumber = ipHeader->ip_p;
            if (ipProtocolNumber != IPPROTO_UDP ||
                ipProtocolNumber != IPPROTO_TCP)
            {
                break;
            }


            MESSAGE_ShrinkPacket(node,
                                 msg,
                                 sizeof(IpHeaderType));

            if (ipProtocolNumber == IPPROTO_UDP)
            {
                Udp_HandleIcmpMessage (node,
                                       msg,
                                       icmpHeader->icmpMessageType,
                                       icmpHeader->icmpCode);
            }
            else if (ipProtocolNumber == IPPROTO_TCP)
            {
                Tcp_HandleIcmpMessage(node,
                                      msg,
                                      icmpHeader->icmpMessageType,
                                      icmpHeader->icmpCode);
            }
            break;
       }

        case ICMP_DESTINATION_UNREACHABLE:
        {
            if (icmpHeader->icmpCode == ICMP_NETWORK_UNREACHABLE)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got network unreachable message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpNetworkUnreacableRecd)++;
            }
            else if (icmpHeader->icmpCode == ICMP_HOST_UNREACHABLE)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got host unreachable message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpHostUnreacableRecd)++;
            }
            else if (icmpHeader->icmpCode == ICMP_PROTOCOL_UNREACHABLE)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got protocol unreachable message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpProtocolUnreacableRecd)++;
            }
            else if (icmpHeader->icmpCode == ICMP_PORT_UNREACHABLE)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got port unreachable message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpPortUnreacableRecd)++;
            }
            else if (icmpHeader->icmpCode == ICMP_DGRAM_TOO_BIG)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got fragmenattion required message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpFragNeededRecd)++;
            }
            else if (icmpHeader->icmpCode == ICMP_SOURCE_ROUTE_FAILED)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got soure route failed message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpSourceRouteFailedRecd)++;
            }
            else if (icmpHeader->icmpCode ==
                                        ICMP_DESTINATION_NETWORK_UNKNOWN)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got destination network unknown"
                       "message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpDestinationNetworkUnknownRecd)++;
            }
            else if (icmpHeader->icmpCode ==
                                           ICMP_DESTINATION_HOST_UNKNOWN)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got destination host unknown"
                       "message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpDestinationHostUnknownRecd)++;
            }
            else if (icmpHeader->icmpCode ==
                                     ICMP_DESTINATION_NETWORK_PROHIBITED)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got destination network prohibited"
                       "message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpNetworkAdminProhibitedRecd)++;
            }
            else if (icmpHeader->icmpCode ==
                                        ICMP_DESTINATION_HOST_PROHIBITED)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got destination host prohibited"
                       "message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpHostAdminProhibitedRecd)++;
            }
            else if (icmpHeader->icmpCode ==
                                            ICMP_NETWORK_UNREACHABLE_TOS)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got network unreachable for TOS"
                       "message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpNetworkUnreachableForTOSRecd)++;
            }
            else if (icmpHeader->icmpCode == ICMP_HOST_UNREACHABLE_TOS)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got host unreachable for TOS"
                       "message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpHostUnreachableForTOSRecd)++;
            }
            else if (icmpHeader->icmpCode ==
                                           ICMP_COMMUNICATION_PROHIBITED)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got communication prohobited"
                       "message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpCommAdminProhibitedRecd)++;
            }
            else if (icmpHeader->icmpCode ==
                                          ICMP_HOST_PRECEDENCE_VIOLATION)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got host precedence violation"
                       "message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpHostPrecedenceViolationRecd)++;
            }
            else if (icmpHeader->icmpCode == ICMP_PRECEDENCE_CUTOFF)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(sourceAddress, srcAddr);
                printf("Node %d got precedence cutoff message from %s\n"
                    ,node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpPrecedenceCutoffInEffectRecd)++;
            }

            MESSAGE_RemoveHeader(node,
                                 msg,
                                 sizeof(IcmpHeader),
                                 TRACE_ICMP);

            IpHeaderType *ipHeader = (IpHeaderType*)MESSAGE_ReturnPacket
                                     (msg);
            ipProtocolNumber = ipHeader->ip_p;
            if (ipProtocolNumber != IPPROTO_UDP ||
                ipProtocolNumber != IPPROTO_TCP)
            {
                break;
            }

            MESSAGE_ShrinkPacket(node,
                                 msg,
                                 sizeof(IpHeaderType));

            if (ipProtocolNumber == IPPROTO_UDP)
            {
                Udp_HandleIcmpMessage (node,
                                       msg,
                                       icmpHeader->icmpMessageType,
                                       icmpHeader->icmpCode);
            }
            else if (ipProtocolNumber == IPPROTO_TCP)
            {
                Tcp_HandleIcmpMessage(node,
                                      msg,
                                      icmpHeader->icmpMessageType,
                                      icmpHeader->icmpCode);
            }
            break;
        }

        case ICMP_SOURCE_QUENCH:
        {
            (icmp->icmpErrorStat.icmpSrcQuenchRecd)++;
#ifdef DEBUG_ICMP_ERROR_MESSAGES
            char srcAddr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(sourceAddress, srcAddr);
            printf("Node %d got Source Quench Message from %s\n",
                            node->nodeId, srcAddr);
#endif

            MESSAGE_RemoveHeader(node,
                                 msg,
                                 sizeof(IcmpHeader),
                                 TRACE_ICMP);

            IpHeaderType *ipHeader = (IpHeaderType*)MESSAGE_ReturnPacket
                                     (msg);
            ipProtocolNumber = ipHeader->ip_p;
            if (ipProtocolNumber != IPPROTO_UDP ||
                ipProtocolNumber != IPPROTO_TCP)
            {
                break;
            }

            MESSAGE_ShrinkPacket(node,
                                 msg,
                                 sizeof(IpHeaderType));

            if (ipProtocolNumber == IPPROTO_UDP)
            {
                Udp_HandleIcmpMessage (node,
                                       msg,
                                       icmpHeader->icmpMessageType,
                                       icmpHeader->icmpCode);
            }
            else if (ipProtocolNumber == IPPROTO_TCP)
            {
                Tcp_HandleIcmpMessage(node,
                                      msg,
                                      icmpHeader->icmpMessageType,
                                      icmpHeader->icmpCode);
            }
            break;
        } //End ICMP_SOURCE_QUENCH

        case ICMP_PARAMETER_PROBLEM:
        {
            (icmp->icmpErrorStat.icmpParameterProblemRecd)++;
#ifdef DEBUG_ICMP_ERROR_MESSAGES
            char srcAddr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(sourceAddress, srcAddr);
            printf("Node %d got ICMP Parameter Problem Message from %s\n"
                ,node->nodeId, srcAddr);
#endif
            MESSAGE_RemoveHeader(node,
                                 msg,
                                 sizeof(IcmpHeader),
                                 TRACE_ICMP);

            IpHeaderType *ipHeader = (IpHeaderType*)MESSAGE_ReturnPacket
                                     (msg);

            ipProtocolNumber = ipHeader->ip_p;
            if (ipProtocolNumber != IPPROTO_UDP ||
                ipProtocolNumber != IPPROTO_TCP)
            {
                break;
            }

            MESSAGE_ShrinkPacket(node,
                                 msg,
                                 sizeof(IpHeaderType));

            if (ipProtocolNumber == IPPROTO_UDP)
            {
                Udp_HandleIcmpMessage (node,
                                       msg,
                                       icmpHeader->icmpMessageType,
                                       icmpHeader->icmpCode);
            }
            else if (ipProtocolNumber == IPPROTO_TCP)
            {
                Tcp_HandleIcmpMessage(node,
                                      msg,
                                      icmpHeader->icmpMessageType,
                                      icmpHeader->icmpCode);
            }
            break;

        } //End ICMP_PARAMETER_PROBLEM

        case ICMP_SECURITY_FAILURES:
        {
            (icmp->icmpErrorStat.icmpSecurityFailedRecd)++;
#ifdef DEBUG_ICMP_ERROR_MESSAGES
            char srcAddr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(sourceAddress, srcAddr);
            printf("Node %d got ICMP Security Failure"
                   "Message from %s\n"
                   ,node->nodeId, srcAddr);
#endif
            MESSAGE_RemoveHeader(node,
                                 msg,
                                 sizeof(IcmpHeader),
                                 TRACE_ICMP);

            IpHeaderType *ipHeader = (IpHeaderType*)MESSAGE_ReturnPacket
                                     (msg);

            ipProtocolNumber = ipHeader->ip_p;
            if (ipProtocolNumber != IPPROTO_UDP ||
                ipProtocolNumber != IPPROTO_TCP)
            {
                break;
            }

            MESSAGE_ShrinkPacket(node,
                                 msg,
                                 sizeof(IpHeaderType));

            if (ipProtocolNumber == IPPROTO_UDP)
            {
                Udp_HandleIcmpMessage (node,
                                       msg,
                                       icmpHeader->icmpMessageType,
                                       icmpHeader->icmpCode);
            }
            else if (ipProtocolNumber == IPPROTO_TCP)
            {
                Tcp_HandleIcmpMessage(node,
                                      msg,
                                      icmpHeader->icmpMessageType,
                                      icmpHeader->icmpCode);
            }
            break;

        } //End ICMP_SECURITY_FAILURE


        default:
        {
#ifdef IPNE_INTERFACE
            printf(
                "ICMP: Node %d received unknown ICMP type %d while running "
                "IPNE\n",
                node->nodeId,
                icmpHeader->icmpMessageType);
            break;
#else
            printf("\n ICMP: This is not a ICMP type\n");
            assert(FALSE);
#endif /* IPNE_INTERFACE */
        }

    } //End switch (icmpType)

    MESSAGE_Free(node, msg);
}


/*
 * FUNCTION:   NetworkIcmpHandleProtocolEvent()
 * PURPOSE:    This function handles different type of Icmp events.
 *             This function will be called from NetworkIpLayer() in
 *             nwip.pc file if event is icmp event type.
 * RETURN:     NULL
 * ASSUMPTION: None
 * PARAMETERS: node,   node which is allocating message
 *             msg,    Abstract Message (Packet) to handle.
 */

void NetworkIcmpHandleProtocolEvent(Node *node, Message *msg)
{

    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    switch (msg->eventType)
    {
        case MSG_NETWORK_IcmpRouterAdvertisement:
        {
            /*Generate Router Advertisement Message and rescedule
              for the next*/

            int interfaceIndex = *((int*) MESSAGE_ReturnInfo(msg));

            RouterInterfaceStructure *routerInterfaceStructure =
                              (RouterInterfaceStructure*)
                                  icmp->interfaceStruct[interfaceIndex];

            Message *routerAdMsg;

#ifdef DEBUG
            NodeAddress interfaceIpAddress = NetworkIpGetInterfaceAddress(
                                                             node,
                                                             interfaceIndex);
#endif
            clocktype delayForAdvertisement;

            #ifdef DEBUG
            {
                char clockStr[100];
                ctoa(node->getNodeTime(), clockStr);

                printf("Node %u got MSG_NETWORK_IcmpRouterAdvertisement"
                       " event at time %s\n", node->nodeId, clockStr);
            }
            #endif

            // Calculate the delay time for next Advertisement message

            // Uniform between minAdverInterval and maxAdverInterval
            delayForAdvertisement = (clocktype)
                ((RANDOM_nrand(icmp->seed)) %
                (clocktype) (icmp->parameter.maxAdverInterval -
                icmp->parameter.minAdverInterval + 1) +
                icmp->parameter.minAdverInterval);

            if (routerInterfaceStructure->advertisementNumber <
                                             ICMP_MAX_INITIAL_ADVERTISEMENTS)
            {
                // First few advertisement must not be longer than
                // ICMP_MAX_INITIAL_ADVERT_INTERVAL
                if (delayForAdvertisement > ICMP_MAX_INITIAL_ADVERT_INTERVAL)
                {
                    delayForAdvertisement = ICMP_MAX_INITIAL_ADVERT_INTERVAL;
                }
            }

            // Sending advertisement in response to solicitation.
            if (routerInterfaceStructure->solicitationFlag == TRUE)
            {
                #ifdef DEBUG
                {
                    printf("    due to solicitation\n");
                }
                #endif

                NetworkIcmpGenerateRouterDiscoveryMessage(node,
                                                   ICMP_AD_ADDRESS,
                                                   ICMP_ROUTER_ADVERTISEMENT,
                                                   0,
                                                   interfaceIndex);

                routerInterfaceStructure->solicitationFlag = FALSE;
                routerInterfaceStructure->advertiseFlag = FALSE;
                routerInterfaceStructure->advertisementNumber++;

                routerAdMsg = MESSAGE_Alloc(node,
                                        NETWORK_LAYER,
                                        NETWORK_PROTOCOL_ICMP,
                                        MSG_NETWORK_IcmpRouterAdvertisement);

                MESSAGE_InfoAlloc(node, routerAdMsg, sizeof(int));
                *((int*) MESSAGE_ReturnInfo(routerAdMsg)) = interfaceIndex;

                ActionData acnData;
                acnData.actionType = SEND;
                acnData.actionComment = NO_COMMENT;
                TRACE_PrintTrace(node, routerAdMsg, TRACE_NETWORK_LAYER,
                          PACKET_OUT, &acnData);

                MESSAGE_Send(node, routerAdMsg, delayForAdvertisement);

            } //End if

            else if ((routerInterfaceStructure->solicitationFlag == FALSE)
                      && (routerInterfaceStructure->advertiseFlag == FALSE))
            {
                assert(0);
                //routerInterfaceStructure->advertiseFlag = TRUE;

            } //End else if

            // Sending advertisement periodically.
            else if (routerInterfaceStructure->advertiseFlag == TRUE)
            {
                #ifdef DEBUG
                {
                    printf("    due to periodic update\n");
                }
                #endif

                NetworkIcmpGenerateRouterDiscoveryMessage(node,
                                                   ICMP_AD_ADDRESS,
                                                   ICMP_ROUTER_ADVERTISEMENT,
                                                   0,
                                                   interfaceIndex);

                routerInterfaceStructure->advertisementNumber++;

                routerAdMsg = MESSAGE_Alloc(node,
                                        NETWORK_LAYER,
                                        NETWORK_PROTOCOL_ICMP,
                                        MSG_NETWORK_IcmpRouterAdvertisement);

                MESSAGE_InfoAlloc(node, routerAdMsg, sizeof(int));
                *((int*) MESSAGE_ReturnInfo(routerAdMsg)) = interfaceIndex;

                ActionData acnData;
                acnData.actionType = SEND;
                acnData.actionComment = NO_COMMENT;
                TRACE_PrintTrace(node, routerAdMsg, TRACE_NETWORK_LAYER,
                          PACKET_OUT, &acnData);

                MESSAGE_Send(node, routerAdMsg, delayForAdvertisement);

            } //End else if

            break;

        } // End MSG_NETWORK_IcmpRouterAdvertisement

        case MSG_NETWORK_IcmpRouterSolicitation:
        {
            /*Generate Router Solicitation Message and rescedule
            for the next*/

            int interfaceIndex = *((int *) MESSAGE_ReturnInfo(msg));

            HostInterfaceStructure *hostInterfaceStructure =
                                       (HostInterfaceStructure *)
                                       icmp->interfaceStruct[interfaceIndex];

            #ifdef DEBUG
            {
                char clockStr[100];
                ctoa(node->getNodeTime(), clockStr);

                printf("Node %u got MSG_NETWORK_IcmpRouterSolicitation"
                       " event at time %s\n", node->nodeId, clockStr);
            }
            #endif

            if ((hostInterfaceStructure->alreadyGotRouterSolicitationMessage
                 == FALSE) &&
                 ((int) hostInterfaceStructure->solicitationNumber <
                     icmp->parameter.maxNumSolicits))
            {
                clocktype delayForSolicitation;
                Message *routerSolicitationMsg;

                NetworkIcmpGenerateRouterDiscoveryMessage(node,
                                                   ICMP_SOLI_ADDRESS,
                                                   ICMP_ROUTER_SOLICITATION,
                                                   0,
                                                   interfaceIndex);

                hostInterfaceStructure->solicitationNumber++;

                delayForSolicitation = ICMP_SOLICITATION_INTERVAL;

                routerSolicitationMsg = MESSAGE_Alloc(node,
                                         NETWORK_LAYER,
                                         NETWORK_PROTOCOL_ICMP,
                                         MSG_NETWORK_IcmpRouterSolicitation);

                MESSAGE_InfoAlloc(node, routerSolicitationMsg, sizeof(int));
                *((int *)MESSAGE_ReturnInfo(routerSolicitationMsg)) =
                                                              interfaceIndex;

                ActionData acnData;
                acnData.actionType = SEND;
                acnData.actionComment = NO_COMMENT;
                TRACE_PrintTrace(node,
                                routerSolicitationMsg,
                                TRACE_NETWORK_LAYER,
                                PACKET_OUT,
                                &acnData);

                MESSAGE_Send(node,
                              routerSolicitationMsg,
                              delayForSolicitation);
            } //End if
            else
            {
                #ifdef DEBUG
                    printf("   already receivied solicitation, so ignore\n");
                #endif
            }

            break;

        } //End MSG_NETWORK_IcmpRouterSolicitation

        case MSG_NETWORK_IcmpValidationTimer:
        {
            /*
             * This Timer is required when UpdateRouterList(..) function is
             * called for update or insert any row in the Router_List to set
             * timer with the value of lifeTime field of
             * Router Advertisement Message.
             * When the timer is fired validation of this row become FALSE.
             */
            NodeAddress ipAddress = *((NodeAddress *)
                                                    MESSAGE_ReturnInfo(msg));
            int index;

            for (index = 0; index < ICMP_DEFAULT_HOST_ROUTERLIST_SIZE;
                                                                     index++)
            {
                if ((icmp->hostRouterList[index].routerAddr == ipAddress)
                     && (icmp->hostRouterList[index].systemConfiguration ==
                         FALSE))
                {
                    icmp->hostRouterList[index].count--;

                    if (icmp->hostRouterList[index].count == 0)
                    {
                        icmp->hostRouterList[index].validRow = FALSE;

                        // Inform listener of timeout.
                        NetworkIcmpCallRouterTimeoutFunction(node,
                                                                  ipAddress);

                    } //End if

                    break;

                } //End if

            } //End for

            break;

        } // End MSG_NETWORK_IcmpValidationTimer

        case MSG_NETWORK_IcmpRedirectRetryTimer:
        {
            NetworkIcmpDeletecacheEntry (node, msg);
            break;
        }
        default:
        {
            ERROR_Assert(FALSE, "\n ICMP: Event Type is not"
                         " ICMP Event Type");
        }

    } //End switch (eventType)

    MESSAGE_Free(node, msg);
}

/*
 * FUNCTION:   NetworkIcmpHandleEcho()
 * PURPOSE:    This function handles an ICMP echo packet by initiating an
 * ECHO REPLY.
 * RETURN:     None
 * ASSUMPTION: None
 * PARAMETERS: node,     node in which Icmp message will be created.
 *             msg, echo packet received.
 *             sourceAddress, IP Address of the source of the echo packet
 *             interfaceIndex, interface on which the packet was received
 */

void NetworkIcmpHandleEcho( Node *node,
                              Message *msg,
                              NodeAddress sourceAddress,
                              int interfaceIndex)
{
    unsigned short icmpType = ICMP_ECHO_REPLY;
    unsigned short icmpCode = 0;

    IpHeaderType *ipHeader;
    int size;
    Message *icmpPacket;
    char *icmpData;
    char *origPacket;
    int interfaceId;
    char *newRecordRoute = NULL;
    char *newTimeStamp = NULL;
    NodeAddress *newSourceRoute = NULL;
    int recordRoutelen = 0;
    int sourceRoutelen = 0;
    int timeStamplen = 0;
    IcmpHeader *icmpHeader;
    short idNumber, sequenceNumber;
    NodeAddress immediateDestination = 0;

    NetworkDataIp *ip = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;

    ipHeaderSizeInfo *ipHeaderSize = NULL;
    ipHeaderSize = (ipHeaderSizeInfo *)MESSAGE_ReturnInfo(msg,
                                                    INFO_TYPE_IpHeaderSize);
    msg->packet -= ipHeaderSize->size;
    ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

    if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst) ||
        ipHeader->ip_dst == ANY_DEST)
    {
        return;
    }

    for (interfaceId = 0; interfaceId < node->numberInterfaces;
         interfaceId++)
    {
        if (NetworkIpGetInterfaceBroadcastAddress(node,interfaceId)
                                                   == ipHeader->ip_dst)
        {
            return;
        }
    }
    if (IpHeaderSize(ipHeader) != sizeof(IpHeaderType))
    {
        IpOptionsHeaderType *sourceRouteOption =
                                  IpHeaderSourceRouteOptionField(ipHeader);
        IpOptionsHeaderType *recordRouteOption =
                                  IpHeaderRecordRouteOptionField(ipHeader);
        IpOptionsHeaderType *timeStampOption =
                                  IpHeaderTimestampOptionField(ipHeader);
        if (recordRouteOption)
        {
            recordRoutelen = recordRouteOption->len + 1;
            newRecordRoute = (char *)MEM_malloc(recordRoutelen);
            memcpy(newRecordRoute,
                  (char *)recordRouteOption,
                  recordRoutelen - 1);
            newRecordRoute[recordRoutelen - 1] = '\0';
        }
        if (timeStampOption)
        {
            timeStamplen = timeStampOption->len;
            newTimeStamp = (char *)MEM_malloc(timeStamplen);
            memset(newTimeStamp, 0, timeStamplen);
            memcpy(newTimeStamp, (char *)timeStampOption, timeStamplen);
        }
        if (sourceRouteOption)
        {
            NodeAddress *source = &sourceAddress;
            char *FirstAddress = ((char *) sourceRouteOption +
                                                sizeof(IpOptionsHeaderType));

            //move pointer back to obtain the next immediate destination to
            //be inserted in IP Header

            memcpy((char *)&immediateDestination,
                   (char *)sourceRouteOption + sourceRouteOption->ptr -
                   (sizeof(NodeAddress)) - 1,
                    sizeof(NodeAddress));
            sourceRoutelen = (sourceRouteOption->len -
                              sizeof(IpOptionsHeaderType)) /
                              sizeof(NodeAddress);
            newSourceRoute = (NodeAddress *)
                            MEM_malloc(sourceRoutelen * sizeof(NodeAddress));
            memset(newSourceRoute, 0,
                                       sourceRoutelen * sizeof(NodeAddress));
            memcpy(newSourceRoute, source, sizeof(NodeAddress));
            source = newSourceRoute + 1;
            memcpy(source, FirstAddress,
                                 (sourceRoutelen - 1) * sizeof(NodeAddress));
            newSourceRoute = ReverseArray(newSourceRoute, sourceRoutelen);
        }
    }

    msg->packet += ipHeaderSize->size;
    icmpHeader = (IcmpHeader*)(msg->packet);
    idNumber = icmpHeader->Option.IcmpEchoTimeSecTrace.idNumber;
    sequenceNumber = icmpHeader->Option.IcmpEchoTimeSecTrace.sequenceNumber;
    MESSAGE_RemoveHeader(node,
                         msg,
                         sizeof(IcmpHeader),
                         TRACE_ICMP);

    icmpPacket = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               NETWORK_PROTOCOL_ICMP,
                               MSG_NETWORK_IcmpData);

    size = msg->packetSize;

    MESSAGE_PacketAlloc(node,
                        icmpPacket,
                        size,
                        TRACE_ICMP);

    origPacket = MESSAGE_ReturnPacket(msg);
    icmpData = MESSAGE_ReturnPacket(icmpPacket);
    memcpy(icmpData, origPacket, (int) size);

    MESSAGE_ExpandPacket(node, icmpPacket, sizeof(IcmpHeader));

    icmpHeader = (IcmpHeader*) MESSAGE_ReturnPacket(icmpPacket);

    memset(icmpHeader, 0, sizeof(IcmpHeader));

    NetworkIcmpSetIcmpHeader(node,
                             NULL,
                             icmpPacket,
                             icmpType,
                             icmpCode,
                             idNumber,
                             sequenceNumber);

    (icmp->icmpStat.icmpEchoReplyGenerated)++;

    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, icmpPacket, TRACE_NETWORK_LAYER,
              PACKET_OUT, &acnData);

    NetworkIcmpSendPacketToIp(node,
                              icmpPacket,
                              0,
                              interfaceIndex,
                              sourceAddress,
                              0,
                              newSourceRoute,
                              sourceRoutelen,
                              newRecordRoute,
                              recordRoutelen,
                              newTimeStamp,
                              timeStamplen,
                              immediateDestination);


}

/*
 * FUNCTION:   NetworkIcmpHandleRedirect()
 * PURPOSE:    This function handles an ICMP Redirect message
 * RETURN:     None
 * ASSUMPTION: None
 * PARAMETERS: node,     node in which Icmp message will be created.
 *             msg, Redirect message received.
 *             sourceAddress, IP Address of the source of the Redirect packet
 *             interfaceIndex, interface on which the packet was received
 */

void NetworkIcmpHandleRedirect(Node *node,
                              Message *msg,
                              NodeAddress sourceAddress,
                              int interfaceIndex)
{
    IcmpHeader *icmpHeader = (IcmpHeader*) msg->packet;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;

    NodeAddress destAddressMask = ANY_IP;

    NodeAddress nextHopAddress = icmpHeader->Option.gatewayAddr;
    unsigned char icmpCode = icmpHeader->icmpCode;
    if (icmpCode == 0 || icmpCode == 1 || icmpCode == 2 ||
    icmpCode == 3)
    {
        // Treating the Network and host redirects in the same manner.
        destAddressMask = ANY_IP;
    }
    MESSAGE_RemoveHeader(node, msg, sizeof(IcmpHeader), TRACE_ICMP);

    IpHeaderType *origIpHeader = (IpHeaderType *) msg->packet;


    NodeAddress destAddress = origIpHeader->ip_dst;
    destAddress = MaskIpAddress(destAddress, destAddressMask);

#ifdef ICMP_DEBUG
    printf("Redirect has code %hu\n", icmpCode);

    printf("This is the forwarding table before update\n");
    NetworkPrintForwardingTable(node);
#endif

    NetworkRoutingProtocolType type;
    type = NetworkIpGetUnicastRoutingProtocolType(node, interfaceIndex);

    //interfaces running a routing protocol should not process ICMP redirect
    //messages unless the option is enabled (enabled by default).
    if (type != ROUTING_PROTOCOL_NONE
        && icmp->parameter.redirectOverrideRoutingProtocol == FALSE)
    {
         ERROR_ReportError(
             "If ICMP-REDIRECT-OVERRIDE-ROUTING is disabled, non-static "
             "routes in the forwarding table cannot be overwritten by "
             "an ICMP redirect.\n");
    }
    else
    {
        NetworkUpdateForwardingTable(
            node,
            destAddress,
            destAddressMask,
            nextHopAddress,
            interfaceIndex,
            1,
            ROUTING_PROTOCOL_ICMP_REDIRECT);
    }


    #ifdef ICMP_DEBUG
        printf("This is the forwarding table after update\n");
        NetworkPrintForwardingTable(node);
    #endif
}

/*
 * FUNCTION:   NetworkIcmpCreateIcmpPacket()
 * PURPOSE:    This function create Icmp message and fillup data portion.
 * RETURN:     Message pointer
 * ASSUMPTION: None
 * PARAMETERS: node,     node in which Icmp message will be created.
 *             icmpType, type of the Icmp message which will be created.
 */

static Message* NetworkIcmpCreateIcmpPacket(Node *node,
                                            unsigned short icmpType,
                                            unsigned short icmpCode,
                                            int interfaceIndex)
{
    Message *newMsg;
    IcmpHeader *icmpHeader;
    IcmpData *icmpData;

    NetworkDataIp *ip = (NetworkDataIp*) node->networkData.networkVar;

    newMsg = MESSAGE_Alloc(node,
                            NETWORK_LAYER,
                            NETWORK_PROTOCOL_ICMP,
                            MSG_NETWORK_IcmpData);

#ifdef ENTERPRISE_LIB
    // If Agent advertisement message comes from any mobility agent, the data
    // packet in the message structure is created by appending Mobility Agent
    // Advertisement Extension with normal ICMP message.

    BOOL isPacketForMobileIp = FALSE;
    NetworkDataMobileIp* mobileIp = NULL;

    if (ip->mobileIpStruct)
    {
        mobileIp = (NetworkDataMobileIp*) ip->mobileIpStruct;
        if ((mobileIp->agent == BothAgent) ||
                (mobileIp->agent == HomeAgent) ||
                (mobileIp->agent == ForeignAgent))
        {
            isPacketForMobileIp = TRUE;
        }
    }

    #ifdef DEBUG
        printf("Create pack for mobility agent\n");
    #endif

    if (isPacketForMobileIp)
    {
        MESSAGE_PacketAlloc(
                      node,
                      newMsg,
                      sizeof(IcmpData) + sizeof(AgentAdvertisementExtension),
                      TRACE_ICMP);

        icmpData = (IcmpData*) newMsg->packet;
        memset(icmpData,
               0,
               sizeof(IcmpData) + sizeof(AgentAdvertisementExtension));
        #ifdef DEBUG
            printf("Create pack for MobileIP by ICMP\n");
        #endif
    }
    else
#endif // ENTERPRISE_LIB
    {
        MESSAGE_PacketAlloc(node, newMsg, sizeof(IcmpData), TRACE_ICMP);

        icmpData = (IcmpData*) newMsg->packet;

        memset(icmpData, 0, sizeof(IcmpData));
    }

    switch (icmpType)
    {
        case ICMP_ROUTER_ADVERTISEMENT:
        {
            NodeAddress interfaceAddr = NetworkIpGetInterfaceAddress(
                    node, interfaceIndex);

            icmpData->RouterAdvertisementData.routerAddress =
                              NetworkIpGetInterfaceAddress(node,
                                                           interfaceIndex);

            icmpData->RouterAdvertisementData.preferenceLevel =
                                                ICMP_AD_PREFERNCE_LEVEL;
#ifdef ENTERPRISE_LIB
            if (ip->mobileIpStruct)
            {
                if ((mobileIp->agent == BothAgent) ||
                        (mobileIp->agent == HomeAgent) ||
                        (mobileIp->agent == ForeignAgent))
                {
                    MobileIpCreateAgentAdvExt(node,
                                              interfaceAddr,
                                              newMsg);
                }
            }
#endif // ENTERPRISE_LIB

            break;

        } //End ROUTER_ADVERTISEMENT

        case ICMP_ROUTER_SOLICITATION:
        {
            break;
        } //End ROUTER_SOLICITATION

        default:
        {
            assert(FALSE);
        }
    } //End switch (icmpType)

    MESSAGE_AddHeader(node, newMsg, sizeof(IcmpHeader), TRACE_ICMP);

    icmpHeader = (IcmpHeader*) newMsg->packet;

    memset(icmpHeader, 0, sizeof(IcmpHeader));

    return newMsg;
}


/*
 * FUNCTION:   NetworkIcmpSendPacketToIp()
 * PURPOSE:    This function send the Icmp message and destination address
 *             to Ip layer for creating Ipdatagram and sending the message
 *             to another node.
 * RETURN:     NULL
 * ASSUMPTION: None
 * PARAMETERS: node,          node which is allocating message
 *             icmpPacket,    icmp message
 *             ttl,           time to life of this message.
 *             interfaceIndex,   in which interface this message will be send
 *             destinationAddress, destination address of this message
 *             priority, TOS value
 *             newSourceRoute, pointer to source route array
 *             sourceRouteLen, no of elements in the source route array
 *             newRecordRoute, pointer to record route option
 *             recordRouteLen, length of record route option
  *            newTimeStamp, pointer to timestamp option
 *             timeStamplen, length of timestamp option
 *             immediateDestination, used in Source Routing
 */

static void NetworkIcmpSendPacketToIp(Node * node,
                                      Message *icmpPacket,
                                      unsigned int ttl,
                                      unsigned int interfaceIndex,
                                      NodeAddress destinationAddress,
                                      TosType priority,
                                      NodeAddress *newSourceRoute,
                                      int sourceRouteLen,
                                      char *newRecordRoute,
                                      int recordRouteLen,
                                      char *newTimeStamp,
                                      int timeStamplen,
                                      NodeAddress immediateDestination)
{
    NodeAddress sourceAddress;
    if (interfaceIndex != (unsigned int)ANY_INTERFACE &&
        interfaceIndex != (unsigned int)CPU_INTERFACE)
    {
        sourceAddress = NetworkIpGetInterfaceAddress(node, interfaceIndex);
    }
    else
    {
        sourceAddress = (unsigned int)ANY_IP;
    }
    if (ttl == 0)
    {
         ttl = (unsigned int)IPDEFTTL;/* default ttl is 64, from RFC 1340 */
    }

    // this is for adding IpHeader & Routing packet

    if (destinationAddress != (unsigned int)ANY_DEST &&
        newSourceRoute == NULL && newRecordRoute == NULL &&
        newTimeStamp == NULL)
    {

        NetworkIpSendRawMessage(node,
                                icmpPacket,
                                sourceAddress,
                                destinationAddress,
                                ANY_INTERFACE,
                                priority,
                                IPPROTO_ICMP,
                                ttl);
    } //End if

    else if (destinationAddress == (unsigned int)ANY_DEST &&
             newSourceRoute == NULL && newRecordRoute == NULL
             && newTimeStamp == NULL)
    {
        NetworkIpSendRawMessageToMacLayer(
                                    node,
                                    icmpPacket,
                                    sourceAddress,
                                    destinationAddress,
                                    priority,
                                    IPPROTO_ICMP,
                                    ttl,
                                    interfaceIndex,
                                    destinationAddress);
    }
    else
    {

        if (sourceAddress == (unsigned int)ANY_IP)
        {
            interfaceIndex =
                 NetworkGetInterfaceIndexForDestAddress(node,
                                                        destinationAddress);

            sourceAddress = NetworkIpGetInterfaceAddress(node,
                                                            interfaceIndex);
        }

        AddIpHeader(
            node,
            icmpPacket,
            sourceAddress,
            destinationAddress,
            priority,
            IPPROTO_ICMP,
            ttl);

        if (newRecordRoute != NULL)
        {
            //add record route option to ip header
            int oldHeaderSize = IpHeaderSize((IpHeaderType *)
                                                        icmpPacket->packet);
            int newIpOptionSize = 4 * ((((recordRouteLen) - 1) / 4) + 1);
            int newHeaderSize = oldHeaderSize + newIpOptionSize;
            ExpandOrShrinkIpHeader(node, icmpPacket, newHeaderSize);
            char *option = ((char *) icmpPacket->packet + oldHeaderSize);
            memcpy(option, newRecordRoute, recordRouteLen);
            MEM_free(newRecordRoute);
        }
        if (newTimeStamp != NULL)
        {
            //add timestamp option to ip header
            int oldHeaderSize = IpHeaderSize((IpHeaderType *)
                                                        icmpPacket->packet);
            int newIpOptionSize = 4 * ((((timeStamplen) - 1) / 4) + 1);
            int newHeaderSize = oldHeaderSize + newIpOptionSize;
            ExpandOrShrinkIpHeader(node, icmpPacket, newHeaderSize);
            char *option = ((char *) icmpPacket->packet + oldHeaderSize);
            memcpy(option, newTimeStamp, timeStamplen);
            MEM_free(newTimeStamp);
        }
        if (newSourceRoute != NULL)
        {
            IpHeaderType *ipHeader;
            ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(icmpPacket);
            ipHeader->ip_dst = immediateDestination;
            NetworkIpSendPacketToMacLayerWithNewStrictSourceRoute(
                                                           node,
                                                           icmpPacket,
                                                           newSourceRoute,
                                                           sourceRouteLen,
                                                           FALSE);

           MEM_free(newSourceRoute);
        }
        else
        {
            int interfaceIndex =
                 NetworkIpGetInterfaceIndexFromAddress(node, sourceAddress);

            if ((interfaceIndex == -1) || (sourceAddress == (unsigned int)-1))
            {
                MESSAGE_Free(node, icmpPacket);
                return;
            }

            RoutePacketAndSendToMac(node,
                                    icmpPacket,
                                    CPU_INTERFACE,
                                    interfaceIndex,
                                    ANY_IP);
        }
    }
}


/*
 * FUNCTION: NetworkIcmpUpdateRouterList()
 * PURPOSE:  This function update RouterList table if router advertisement
 *           address is in the same subnet.
 * RETURN:   NULL
 * ASSUMPTION: None
 * PARAMETERS: node,    node in which RouterList table is updated.
 *             msg,     router advertisement message.
 */

static void NetworkIcmpUpdateRouterList(Node *node,
                                        Message *msg,
                                        int interfaceIndex)
{
    int freeRow = ICMP_DEFAULT_HOST_ROUTERLIST_SIZE;
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;
    IcmpHeader *icmpHeader = (IcmpHeader*) msg->packet;

    clocktype lifeTimeVar =
                       icmpHeader->Option.RouterAdvertisementHeader.lifeTime
                       * SECOND;

    IcmpData *icmpData;


    ActionData acnData;
    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER, PACKET_IN, &acnData);

    MESSAGE_RemoveHeader(node, msg, sizeof(IcmpHeader), TRACE_ICMP);
    icmpData = (IcmpData*) msg->packet;

    // Make sure in same subnet.  If not, disregard.
    if (!NetworkIcmpCheckIpAddressIsInSameSubnet(node,
                            interfaceIndex,
                            icmpData->RouterAdvertisementData.routerAddress))
    {
         return;
    } //End if

    NetworkIcmpCheckAddressIsExistOrNot(node,
                           &freeRow,
                           icmpData->RouterAdvertisementData.routerAddress);

    // Router already exist in list
    if (freeRow != ICMP_DEFAULT_HOST_ROUTERLIST_SIZE)
    {
         if (icmp->hostRouterList[freeRow].systemConfiguration == FALSE)
         {
              icmp->hostRouterList[freeRow].preferenceLevel =
                           icmpData->RouterAdvertisementData.preferenceLevel;

              icmp->hostRouterList[freeRow].timeToLife = lifeTimeVar;

              // Used with validation timer.
              icmp->hostRouterList[freeRow].count++;

              icmp->hostRouterList[freeRow].interfaceIndex = interfaceIndex;

         } //End if

    }
    // Router not in list, so add it.
    else
    {
        // Get row to insert router.
        NetworkIcmpFindFreeOrMinRowInRouterList(node, &freeRow);

        icmp->hostRouterList[freeRow].validRow = TRUE;

        icmp->hostRouterList[freeRow].routerAddr =
                             icmpData->RouterAdvertisementData.routerAddress;

        icmp->hostRouterList[freeRow].preferenceLevel =
                           icmpData->RouterAdvertisementData.preferenceLevel;

        icmp->hostRouterList[freeRow].timeToLife = lifeTimeVar;
        icmp->hostRouterList[freeRow].count++;
        icmp->hostRouterList[freeRow].interfaceIndex = interfaceIndex;

    } //End else

    if (icmp->hostRouterList[freeRow].systemConfiguration == FALSE)
    {
        Message *routerListMsg = MESSAGE_Alloc(node,
                                           NETWORK_LAYER,
                                           NETWORK_PROTOCOL_ICMP,
                                           MSG_NETWORK_IcmpValidationTimer);

        MESSAGE_InfoAlloc(node, routerListMsg, sizeof(NodeAddress));

        *((NodeAddress*) MESSAGE_ReturnInfo(routerListMsg)) =
                             icmpData->RouterAdvertisementData.routerAddress;


         ActionData acnData;
         acnData.actionType = SEND;
         acnData.actionComment = NO_COMMENT;
         TRACE_PrintTrace(node, routerListMsg, TRACE_NETWORK_LAYER,
                          PACKET_OUT, &acnData);

        MESSAGE_Send(node,
                      routerListMsg,
                      icmp->hostRouterList[freeRow].timeToLife);
    } //End if
}


/*
 * FUNCTION:   NetworkIcmpCheckAddressIsExistOrNot()
 * PURPOSE:    This function check IP address exist in this table.
 * RETURN:     NULL
 * ASSUMPTION: None
 * PARAMETERS: node,        node in which RouterList table is exist.
 *             freeRow,     location of IP address in the table if it exist
 *             routerAddress,  check this IP address is present or not.
 */

static void NetworkIcmpCheckAddressIsExistOrNot(Node *node,
                                                int *freeRow,
                                                NodeAddress routerAddress)
{
    int index;
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    for (index = 0; index < ICMP_DEFAULT_HOST_ROUTERLIST_SIZE; index++)
    {
        if ((icmp->hostRouterList[index].routerAddr == routerAddress)
                && (icmp->hostRouterList[index].validRow == TRUE))
        {
            *freeRow = index;
             break;
        } //End if
    } //End for
}


/*
 * FUNCTION:    NetworkIcmpFindFreeOrMinRowInRouterList()
 * PURPOSE:     This function find a free row or minimum row from
 *              RouterList table.
 * RETURN:      NULL
 * ASSUMPTION:  None
 * PARAMETERS:  node,      node in which RouterList table is exist.
 *              freeRow,   position of this row.
 */

static void NetworkIcmpFindFreeOrMinRowInRouterList(Node *node,
                                                    int *freeRow)
{
    int index;
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    for (index = 0; index < ICMP_DEFAULT_HOST_ROUTERLIST_SIZE; index++)
    {
        if (icmp->hostRouterList[index].validRow == FALSE)
        {
            *freeRow = index;
            break;
        } //End if
    } //End for

     /*
      *  If previous for loop not find free row in Host RouterList Table ,
      *  then with in this if statement, find the row which perferenceLavel
      *  is minimum.
      */

    if (*freeRow == ICMP_DEFAULT_HOST_ROUTERLIST_SIZE)
    {
        //int row;
        unsigned int preferenceLevelValue = 0;

         /*Find first row which is not set as a result
         of system configaration */

        for (index = 0; index < ICMP_DEFAULT_HOST_ROUTERLIST_SIZE; index++)
        {
            if (icmp->hostRouterList[index].systemConfiguration == FALSE)
            {
                //row = index;
                *freeRow = index;
                preferenceLevelValue =
                       icmp->hostRouterList[index].preferenceLevel;
                break;

            } //End if

        } //End for

        // Find minimum row in Host RouterList table.

        for (; index < ICMP_DEFAULT_HOST_ROUTERLIST_SIZE; index++)
        {
            if (icmp->hostRouterList[index].preferenceLevel <
                                                     preferenceLevelValue)
            {
                //row = index;
                *freeRow = index;
                preferenceLevelValue =
                       icmp->hostRouterList[index].preferenceLevel;

            } //End if

        } //End for

    } //End if
}


/*
 * FUNCTION:   NetworkIcmpCheckIpAddressIsInSameSubnet()
 * PURPOSE:    This function check this argument ip address and ip address
 *             of this specified interfaceIndex are in same subnet.
 * RETURN:     BOOL
 * ASSUMPTION: None
 * PARAMETERS: node,              node in which this interfaceIndex belong.
 *             interfaceIndex,    interface index.
 *             ipAddress,         ip address.
 */

static BOOL NetworkIcmpCheckIpAddressIsInSameSubnet(Node *node,
                                                    int interfaceIndex,
                                                    NodeAddress ipAddress)
{
    NodeAddress networkAddress =
                       NetworkIpGetInterfaceNetworkAddress(node,
                                                           interfaceIndex);

    int numHostBits = NetworkIpGetInterfaceNumHostBits(node, interfaceIndex);

    return (IsIpAddressInSubnet(ipAddress, networkAddress, numHostBits));
}


/*
 * FUNCTION:   NetworkIcmpSetIcmpHeader()
 * PURPOSE:    This function fill up Header portion of Icmp Message.
 * RETURN:     NONE
 * ASSUMPTION: NONE
 * PARAMETERS: node,           node which is allocating ICMP message
 *             msg,            message for which ICMP message is generated
 *             icmpPacket,     ICMP message
 *             icmpType,       type of ICMP Router Discovery message
 *             icmpCode,       code of ICMP Router Discovery message
 *             seqOrGatOrPoin, this argument will be indicate the octet
 *                             where error was detected for Parameter
 *                             Problem or gateway address to which path
 *                             is redirected the message in Redirected
 *                             or Sequence Number for Echo /TimeStamp
 *                             Message.
 *            pointer          Reqd for parameter problem error msg
 */

static void NetworkIcmpSetIcmpHeader(Node *node,
                                     Message *msg,
                                     Message *icmpPacket,
                                     unsigned short icmpType,
                                     unsigned short icmpCode,
                                     unsigned int seqOrGatOrPoin,
                                     unsigned short pointer)
{
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;
    IcmpHeader *icmpHeader;
    icmpHeader = (IcmpHeader*)(icmpPacket->packet);
    icmpHeader->icmpMessageType = (unsigned char) icmpType;
    icmpHeader->icmpCode = (unsigned char) icmpCode;
    icmpHeader->icmpCheckSum = 0;

    switch (icmpType)
    {
        case ICMP_ROUTER_ADVERTISEMENT:
        {
            icmpHeader->Option.RouterAdvertisementHeader.numAddr =
                                   ICMP_AD_NUMBER_OF_IP_ADDRESS_IN_INTERFACE;

            icmpHeader->Option.RouterAdvertisementHeader.addrEntrySize =
                                                  ICMP_AD_ADDRESS_ENTRY_SIZE;

            icmpHeader->Option.RouterAdvertisementHeader.lifeTime =
                (unsigned short) (icmp->parameter.adverLifeTime / SECOND);
            break;

        }  //End ROUTER_ADVERTISEMENT

        case ICMP_REDIRECT:
        {
            icmpHeader->Option.gatewayAddr
                = seqOrGatOrPoin;
            break;

        } //End REDIRECT

        case ICMP_ROUTER_SOLICITATION:
        {
            break;

        } //End ROUTER_SOLICITATION

        case ICMP_ECHO_REPLY:
        {
            icmpHeader->Option.IcmpEchoTimeSecTrace.idNumber =
                                                      (short)seqOrGatOrPoin;
            icmpHeader->Option.IcmpEchoTimeSecTrace.sequenceNumber = pointer;
            break;

        } //End ECHO_REPLY

        case ICMP_TIME_STAMP_REPLY:
        {
                        icmpHeader->Option.IcmpEchoTimeSecTrace.idNumber =
                                                      (short)seqOrGatOrPoin;
            icmpHeader->Option.IcmpEchoTimeSecTrace.sequenceNumber = pointer;
            break;

        } //End TIME_STAMP_REPLY

        case ICMP_DESTINATION_UNREACHABLE:
        {
            break;

        } //End DESTINATION_UNREACHABLE

        case ICMP_TIME_EXCEEDED:
        {
            break;

        } //End ICMP_TIME_EXCEEDED

        case ICMP_SOURCE_QUENCH:
        {
            break;

        } //End ICMP_SOURCE_QUENCH

        case ICMP_PARAMETER_PROBLEM:
        {
            icmpHeader->Option.pointer = (unsigned char)pointer;
            break;

        } //End ICMP_PARAMETER_PROBLEM

        case ICMP_SECURITY_FAILURES:
        {
            icmpHeader->Option.IcmpEchoTimeSecTrace.sequenceNumber = 0;
            break;

        } //End SECURITY_FAILURES

        case ICMP_TRACEROUTE:
        {
            icmpHeader->Option.IcmpEchoTimeSecTrace.idNumber =
                                             (unsigned short)seqOrGatOrPoin;
            break;

        } //End ICMP_TRACEROUTE

        default:
        {
            ERROR_Assert(FALSE, "\n ICMP Type is not a valid one");
        }

    }  //End switch

}


/*
 * FUNCTION    NetworkIcmpFinalize()
 * PURPOSE     Print out ICMP statistics, being called at the end.
 * RETURN:     NONE
 * ASSUMPTION: NONE
 * PARAMETERS: node,    ICMP statistics of this node
 */

void NetworkIcmpFinalize(Node * node)
{
    char buf[MAX_STRING_LENGTH];
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    #ifdef DEBUG
        NetworkIcmpPrintRouterList(node);
    #endif

    if (icmp->collectStatistics == TRUE)
    {
        sprintf(buf, "Advertisements Generated = %u",
                icmp->icmpStat.icmpAdvertisementGenerate);
        IO_PrintStat(
            node,
            "Network",
            "ICMP",
            ANY_DEST,
            -1 /* instance Id */,
            buf);

        sprintf(buf, "Advertisements Received = %u",
                icmp->icmpStat.icmpAdvertisementReceive);
        IO_PrintStat(
            node,
            "Network",
            "ICMP",
            ANY_DEST,
            -1 /* instance Id */,
            buf);

        sprintf(buf, "Solicitations Generated = %u",
                icmp->icmpStat.icmpSolicitationGenerate);
        IO_PrintStat(
            node,
            "Network",
            "ICMP",
            ANY_DEST,
            -1 /* instance Id */,
            buf);

        sprintf(buf, "Solicitations Received = %u",
                icmp->icmpStat.icmpSolicitationReceive);
        IO_PrintStat(
            node,
            "Network",
            "ICMP",
            ANY_DEST,
            -1 /* instance Id */,
            buf);

        sprintf(buf, "Echo Messages Received = %u",
            icmp->icmpStat.icmpEchoReceived);
        IO_PrintStat(
            node,
            "Network",
            "ICMP",
            ANY_DEST,
            -1 /* instance Id */,
            buf);

        sprintf(buf, "Echo Reply Messages Generated = %u",
            icmp->icmpStat.icmpEchoReplyGenerated);
        IO_PrintStat(
            node,
            "Network",
            "ICMP",
            ANY_DEST,
            -1 /* instance Id */,
            buf);

        sprintf(buf, "Timestamp Messages Received = %u",
            icmp->icmpStat.icmpTimestampReceived);
        IO_PrintStat(
            node,
            "Network",
            "ICMP",
            ANY_DEST,
            -1 /* instance Id */,
            buf);


        sprintf(buf, "Timestamp Reply Messages Generated = %u",
            icmp->icmpStat.icmpTimestampReplyGenerated);
        IO_PrintStat(
            node,
            "Network",
            "ICMP",
            ANY_DEST,
            -1 /* instance Id */,
            buf);

        sprintf(buf, "TraceRoute Messages Generated = %u",
            icmp->icmpStat.icmpTracerouteGenerated);
        IO_PrintStat(
            node,
            "Network",
            "ICMP",
            ANY_DEST,
            -1 /* instance Id */,
            buf);

    }  //End if
    if (icmp->collectErrorStatistics == TRUE)
    {
        if (icmp->networkUnreachableEnable)
        {
            sprintf(buf, "Network Unreachable Messages sent = %u",
                    icmp->icmpErrorStat.icmpNetworkUnreacableSent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                          -1 /* instance Id */,
                          buf);

            sprintf(buf, "Network Unreachable Messages Received = %u",
                    icmp->icmpErrorStat.icmpNetworkUnreacableRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->hostUnreachableEnable)
        {
            sprintf(buf, "Host Unreachable Messages sent = %u",
                    icmp->icmpErrorStat.icmpHostUnreacableSent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Host Unreachable Messages Received = %u",
                    icmp->icmpErrorStat.icmpHostUnreacableRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->protocolUnreachableEnable)
        {
            sprintf(buf, "Protocol Unreachable Messages sent = %u",
                    icmp->icmpErrorStat.icmpProtocolUnreacableSent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Protocol Unreachable Messages Received = %u",
                    icmp->icmpErrorStat.icmpProtocolUnreacableRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->portUnreachableEnable)
        {
            sprintf(buf, "Port Unreachable Messages sent = %u",
                    icmp->icmpErrorStat.icmpPortUnreacableSent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Port Unreachable Messages Received = %u",
                    icmp->icmpErrorStat.icmpPortUnreacableRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->fragmentationNeededEnable)
        {
            sprintf(buf, "Fragmentation Needed Messages sent = %u",
                    icmp->icmpErrorStat.icmpFragNeededSent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Fragmentation Needed Messages Received = %u",
                    icmp->icmpErrorStat.icmpFragNeededRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->sourceRouteFailedEnable)
        {
            sprintf(buf, "Source Route Failed Message Sent = %u",
                    icmp->icmpErrorStat.icmpSourceRouteFailedSent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Source Route Failed Message Received = %u",
                icmp->icmpErrorStat.icmpSourceRouteFailedRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->sourceQuenchEnable)
        {
            sprintf(buf, "Source Quench Messages sent = %u",
                    icmp->icmpErrorStat.icmpSrcQuenchSent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Source Quench Messages Received = %u",
                    icmp->icmpErrorStat.icmpSrcQuenchRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->TTLExceededEnable)
        {
            sprintf(buf, "TTL Exceeded Messages sent = %u",
                    icmp->icmpErrorStat.icmpTTLExceededSent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "TTL Exceeded Messages Received = %u",
                    icmp->icmpErrorStat.icmpTTLExceededRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->fragmentsReassemblyTimeoutEnable)
        {
            sprintf(buf, "Fragments Reassembly Messages sent = %u",
                    icmp->icmpErrorStat.icmpFragReassemblySent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                          -1 /* instance Id */,
                         buf);

            sprintf(buf, "Fragments Reassembly Messages Received = %u",
                    icmp->icmpErrorStat.icmpFragmReassemblyRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->parameterProblemEnable)
        {
            sprintf(buf, "Parameter Problem Messages sent = %u",
                    icmp->icmpErrorStat.icmpParameterProblemSent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Parameter Problem Messages Received = %u",
                    icmp->icmpErrorStat.icmpParameterProblemRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->securityFailureEnable)
        {
            sprintf(buf, "Security Failure Messages sent = %u",
                icmp->icmpErrorStat.icmpSecurityFailedSent);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Security Failure Messages Received = %u",
                icmp->icmpErrorStat.icmpSecurityFailedRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);
        }

        if (icmp->redirectEnable)
        {
            if (icmp->router == TRUE)
            {
                sprintf(buf, "Redirect Messages sent = %u",
                    icmp->icmpErrorStat.icmpRedirctGenerate);
                IO_PrintStat(
                    node,
                    "Network",
                    "ICMP",
                    ANY_DEST,
                    -1 /* instance Id */,
                    buf);
            }
            sprintf(buf, "Redirect Messages Received = %u",
                icmp->icmpErrorStat.icmpRedirectReceive);
            IO_PrintStat(
                node,
                "Network",
                "ICMP",
                ANY_DEST,
                -1 /* instance Id */,
                buf);
        }

            sprintf(buf, "Destination Network Unknown "
                         "Messages Received = %u",
                icmp->icmpErrorStat.icmpDestinationNetworkUnknownRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Destination Host Unknown Messages Received = %u",
                icmp->icmpErrorStat.icmpDestinationHostUnknownRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Network Administratively Prohibited "
                         "Messages Received = %u",
                icmp->icmpErrorStat.icmpNetworkAdminProhibitedRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Host Administratively Prohibited "
                         "Messages Received = %u",
                icmp->icmpErrorStat.icmpHostAdminProhibitedRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Network Unreachable for TOS "
                         "Messages Received = %u",
                icmp->icmpErrorStat.icmpNetworkUnreachableForTOSRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Host Unreachable for TOS "
                         "Messages Received = %u",
                icmp->icmpErrorStat.icmpHostUnreachableForTOSRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Communication Administratively Prohibited "
                         "Messages Received = %u",
                icmp->icmpErrorStat.icmpCommAdminProhibitedRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Host Precedence Violation Messages Received = %u",
                icmp->icmpErrorStat.icmpHostPrecedenceViolationRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

            sprintf(buf, "Precedence Cutoff In Effect "
                         "Messages Received = %u",
                icmp->icmpErrorStat.icmpPrecedenceCutoffInEffectRecd);
            IO_PrintStat(node,
                         "Network",
                         "ICMP",
                         ANY_DEST,
                         -1 /* instance Id */,
                         buf);

    }  //End if
}


/*
 * FUNCTION:    IcmpPrintRouterList()
 * PURPOSE:     This function print the contain of Host RouterList table.
 * RETURN:      NONE
 * ASSUMPTION:  NONE
 * PARAMETERS:  node,    node in which RouterList table is exist.
 */

static void NetworkIcmpPrintRouterList(Node *node)
{
    int index;
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    if (icmp->router == FALSE)
    {
        printf("\n**************in NODE %u ***************************\n",
                                                               node->nodeId);
        for (index = 0; index < ICMP_DEFAULT_HOST_ROUTERLIST_SIZE; index++)
        {
            char clockStr[MAX_STRING_LENGTH];

            ctoa(icmp->hostRouterList[index].timeToLife, clockStr);
            printf("\nSysCon=%u,Valid=%u,Cout=%u,Interface=%u,"
                      "RouterAddr=%u,PreferenceLavel=%u,lifeTime=%s",
                   icmp->hostRouterList[index].systemConfiguration,
                   icmp->hostRouterList[index].validRow,
                   icmp->hostRouterList[index].count,
                   icmp->hostRouterList[index].interfaceIndex,
                   icmp->hostRouterList[index].routerAddr,
                   icmp->hostRouterList[index].preferenceLevel,
                   clockStr);
        } //End for

        printf("\n****************************************************\n");
    }//if//
}



/*
 * FUNCTION:   NetworkIcmpSetRouterDiscoveryFunction
 * PURPOSE:    Registers router discovery function
 * RETURN:     NULL
 * PARAMETERS: node,    node in which is registering the discovery function.
 *             routerDiscoveryFunctionPtr, discovery function to register.
 */
void NetworkIcmpSetRouterDiscoveryFunction(
    Node *node,
    NetworkIcmpRouterDiscoveryFunctionType routerDiscoveryFunctionPtr)
{
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    ListInsert(node,
               icmp->routerDiscoveryFunctionList,
               node->getNodeTime(),
               (void *) routerDiscoveryFunctionPtr);
}


/*
 * FUNCTION:   NetworkIcmpCallRouterDiscoveryFunction
 * PURPOSE:    Calls discovery function of whom ever registered for it.
 * RETURN:     NULL
 * PARAMETERS: node, node calling the registered discovery function.
 *             msg, router discovery advertisement message.
 *             sourceAddress,  source address
 *             destinationAddress, destination address
 *             interfaceId, interface
 */
void NetworkIcmpCallRouterDiscoveryFunction(
    Node *node,
    Message *msg,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    int interfaceId)
{
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    NetworkIcmpRouterDiscoveryFunctionType routerDiscoveryFunctionPtr;

    ListItem *item = icmp->routerDiscoveryFunctionList->first;

    while (item)
    {
        routerDiscoveryFunctionPtr =
                    (NetworkIcmpRouterDiscoveryFunctionType) item->data;

        (routerDiscoveryFunctionPtr)(node, MESSAGE_Duplicate(node, msg),
                sourceAddress, destinationAddress, interfaceId);

        item = item->next;
    }
}


/*
 * FUNCTION:   NetworkIcmpSetRouterTimeoutFunction
 * PURPOSE:    Registers timeout function
 * RETURN:     NULL
 * PARAMETERS: node,    node in which is registering the timeout function.
 *             routerTimeoutFunctionPtr, timeout function to register.
 */
void NetworkIcmpSetRouterTimeoutFunction(
    Node *node,
    NetworkIcmpRouterTimeoutFunctionType routerTimeoutFunctionPtr)
{
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    ListInsert(node,
               icmp->routerTimeoutFunctionList,
               node->getNodeTime(),
               (void *) routerTimeoutFunctionPtr);
}


/*
 * FUNCTION:   NetworkIcmpCallRouterTimeoutFunction
 * PURPOSE:    Calls timeout function of whom ever registered for it.
 * RETURN:     NULL
 * PARAMETERS: node, node calling the registered timeout function.
 *             routerAddr, router that has timed out.
 */
void NetworkIcmpCallRouterTimeoutFunction(
    Node *node,
    NodeAddress routerAddr)
{
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;

    NetworkIcmpRouterTimeoutFunctionType routerTimeoutFunctionPtr;

    ListItem *item = icmp->routerTimeoutFunctionList->first;

    while (item)
    {
        routerTimeoutFunctionPtr =
                    (NetworkIcmpRouterTimeoutFunctionType) item->data;

        (routerTimeoutFunctionPtr)(node, routerAddr);

        item = item->next;
    }
}

/*
 * FUNCTION:   NetworkIcmpUpdateRedirectCache
 * PURPOSE:    Update ICMP Redirect cache to add a new entry.
 * RETURN:     NULL
 * PARAMETERS: node,           node which is sending ICMP redirect message
 *             ipSource        node to which ICMP Redirect message was sent,
 *             destination   destination for which redirect message was sent
 */

void NetworkIcmpUpdateRedirectCache(Node* node,
                                   NodeAddress ipSource,
                                   NodeAddress destination)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    RedirectCacheInfo* redirectCacheInfo = icmp->redirectCacheInfo;

    RedirectCacheInfo* entry = (RedirectCacheInfo*)
                    MEM_malloc (sizeof(RedirectCacheInfo));
    entry->destination = destination;
    entry->ipSource = ipSource;
    entry->next = NULL;
    if (redirectCacheInfo == NULL)
    {
        icmp->redirectCacheInfo = entry;
        icmp->redirectCacheInfoTail = entry;
    }
    else
    {
        icmp->redirectCacheInfoTail->next = entry;
        icmp->redirectCacheInfoTail = entry;
    }
    Message *redirectCacheExpire = MESSAGE_Alloc(node,
                                   NETWORK_LAYER,
                                   NETWORK_PROTOCOL_ICMP,
                                   MSG_NETWORK_IcmpRedirectRetryTimer);

    MESSAGE_InfoAlloc(node, redirectCacheExpire, sizeof(RedirectCacheInfo));

    RedirectCacheInfo* info = (RedirectCacheInfo*)
                        MESSAGE_ReturnInfo(redirectCacheExpire);

    memcpy(info, entry, sizeof(RedirectCacheInfo));

    MESSAGE_Send(node,
                 redirectCacheExpire,
                 icmp->parameter.redirectRertyTimeout);
}

/*
 * FUNCTION:   NetworkIcmpDeletecacheEntry
 * PURPOSE:    Delete an entry from ICMP Redirect cache.
 * RETURN:     NULL
 * PARAMETERS: node,           node at which Redirect cache timer expired
 *             msg,            Redirect cache expire timer message
 */

void NetworkIcmpDeletecacheEntry (Node* node,Message* msg)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    RedirectCacheInfo* entryTobeDeleted = (RedirectCacheInfo*)
                                            MESSAGE_ReturnInfo(msg);

    RedirectCacheInfo* redirectCacheInfo = icmp->redirectCacheInfo;
    if (redirectCacheInfo->ipSource == entryTobeDeleted->ipSource
          && redirectCacheInfo->destination == entryTobeDeleted->destination)
    {
        ERROR_Assert(redirectCacheInfo == icmp->redirectCacheInfo,
                   "Older entries in Redirect Cache are not deleted yet");
        //if (redirectCacheInfo == icmp->redirectCacheInfo)
        {
            icmp->redirectCacheInfo = icmp->redirectCacheInfo->next;
            MEM_free (redirectCacheInfo);
            redirectCacheInfo = icmp->redirectCacheInfo;
        }
    }
//    MEM_free (entryTobeDeleted);
}

/*
 * FUNCTION:   NetworkIcmpCreateErrorMessage
 * PURPOSE:    Create a ICMP Error message and send it
 * RETURN:     BOOL
 * PARAMETERS: node,           node which generate the ICMP Error Message
 *             msg,            Message of data packet which generate the
 *                             ICMP Error Msg
 *             destinationAddress,  source address of the original Data
 *                                  packet which now becomes the destination
 *                                  address of the ICMP message
 *             interfaceId,    Incoming interface of the original data
 *                             packet which now becomes outgoing interface of
 *                             the ICMP packet
 *             icmpType,       ICMP Error Messgae Type
 *             icmpCode,       ICMP Error Message Code corresponding to Type
 *             pointer         for parameter problem msg
 *             gatewayAddress  for redirect msg
 */

BOOL NetworkIcmpCreateErrorMessage(
    Node *node,
    Message *msg,
    NodeAddress destinationAddress,
    int interfaceId,
    unsigned short icmpType,
    unsigned short icmpCode,
    unsigned short pointer,
    NodeAddress gatewayAddress)
{
    IpHeaderType *ipHeader;
    int interfaceIndex;
    int size,min,ipHeaderSize;
    Message *icmpPacket;
    char *icmpData;
    IcmpHeader *icmpHeader;
    char *origPacket;
    NodeAddress *newSourceRoute = NULL;
    int sourceRoutelen = 0;
    NodeAddress immediateDestination;



    if (icmpType == (unsigned short)ICMP_DESTINATION_UNREACHABLE &&
        icmpCode == (unsigned short)ICMP_PORT_UNREACHABLE)
    {
        /*move the packet pointer of the message to add the transport
         and IP header of the original packet*/

        ipHeaderSizeInfo *ipHeaderSize = NULL;
        ipHeaderSize = (ipHeaderSizeInfo *)MESSAGE_ReturnInfo(msg,
                                                INFO_TYPE_IpHeaderSize);

        MESSAGE_AddHeader(node, msg, sizeof(TransportUdpHeader), TRACE_UDP);
        MESSAGE_AddHeader(node, msg, ipHeaderSize->size, TRACE_IP);
    }

    else if (icmpType == (unsigned short)ICMP_DESTINATION_UNREACHABLE &&
             icmpCode == (unsigned short)ICMP_PROTOCOL_UNREACHABLE)
    {
        /*move the packet pointer of the message to add the
         IP header of the original packet*/

        //IP header has been removed in DeliveryPacket(), we need to
        //add back IP header here.
        //Since MESSAGE_AddHeader() and MESSAGE_RemoveHeader() just
        //move the pointer message->packet. we are able to recover
        //the whole IP header by calling MESSAGE_AddHeader.

        ipHeaderSizeInfo *ipHeaderSize = NULL;
        ipHeaderSize = (ipHeaderSizeInfo *)MESSAGE_ReturnInfo(msg,
                                                INFO_TYPE_IpHeaderSize);

        MESSAGE_AddHeader(node, msg, ipHeaderSize->size, TRACE_IP);
    }

    ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);


    if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst) ||
        ipHeader->ip_dst == ANY_DEST ||
        NetworkIpIsMulticastAddress(node, ipHeader->ip_src) ||
        ipHeader->ip_src == ANY_DEST ||
        NetworkIpIsLoopbackInterfaceAddress(ipHeader->ip_src) ||
        ipHeader->ip_src == 0 ||
       (IpHeaderGetIpMoreFrag(ipHeader->ipFragment)&&
        IpHeaderGetIpFragOffset(ipHeader->ipFragment)!=0))
    {
        return FALSE;
    }

    for (interfaceIndex = 0; interfaceIndex < node->numberInterfaces;
         interfaceIndex++)
    {
        if (NetworkIpGetInterfaceBroadcastAddress(node,interfaceIndex)
                                                   == ipHeader->ip_dst)
        {
            return FALSE;
        }
    }

    if (ipHeader->ip_p == IPPROTO_ICMP)
    {
        char *ip = (char *)ipHeader;
        icmpHeader = (IcmpHeader *)(ip + IpHeaderSize(ipHeader));
        if (icmpHeader->icmpMessageType != (unsigned char)ICMP_ECHO)
        {
            return FALSE;
        }
    }

    IpOptionsHeaderType *ipOption =
                      IpHeaderSourceRouteOptionField(ipHeader);
    if (ipOption)
    {
        int ptr = 0;
        NodeAddress *source = &destinationAddress;
        char *FirstAddress = ((char *) ipOption +
                                                sizeof(IpOptionsHeaderType));
        if ((icmpType == (unsigned short)ICMP_DESTINATION_UNREACHABLE &&
           (icmpCode == (unsigned short)ICMP_NETWORK_UNREACHABLE ||
            icmpCode == (unsigned short)ICMP_HOST_UNREACHABLE ||
            icmpCode == (unsigned short)ICMP_DGRAM_TOO_BIG)) ||
            icmpType == (unsigned short)ICMP_SOURCE_QUENCH)
        {
            ptr = ipOption->ptr - 8;
            if (ptr > 0)
            {
                //move pointer back to obtain the next immediate destination
                //to be inserted in IP Header. As in this case offset has
                //been increased, we will have to move the pointer back
                //by 8 bytes.
                //Also pointer is decremented by 1 to place it properly

                memcpy((char *)&immediateDestination,
                       (char *)ipOption + ptr - 1,
                       sizeof(NodeAddress));
                sourceRoutelen = ptr / sizeof(NodeAddress);
            }
        }
        else
        {
            ptr = ipOption->ptr - (sizeof(NodeAddress));
            if (ptr > 0)
            {
                //move pointer back to obtain the next immediate destination
                //to be inserted in IP Header

                memcpy((char *)&immediateDestination,
                       (char *)ipOption + ptr -1,
                       sizeof(NodeAddress));
                sourceRoutelen = ptr / sizeof(NodeAddress);
            }
        }
        if (ptr > 0)
        {
            newSourceRoute = (NodeAddress *)
                            MEM_malloc(sourceRoutelen * sizeof(NodeAddress));
            memset(newSourceRoute, 0,
                                       sourceRoutelen * sizeof(NodeAddress));
            memcpy(newSourceRoute, source, sizeof(NodeAddress));
            source = newSourceRoute + 1;
            memcpy(source, FirstAddress,
                                  (sourceRoutelen - 1) * sizeof(NodeAddress));
            newSourceRoute = ReverseArray(newSourceRoute, sourceRoutelen);
        }
    }

    size = MESSAGE_ReturnActualPacketSize(msg);
    ipHeaderSize = IpHeaderSize(ipHeader);

#ifdef DEBUG_ICMP_ERROR_MESSAGES
    char srcAddr[MAX_STRING_LENGTH];
    char dstAddr[MAX_STRING_LENGTH];
    TransportUdpHeader* udpHeader;
    tcphdr* tcpHeader;
    printf(" \nOriginal Message :-  \n");
    printf(" Packet size  = %d  \n", MESSAGE_ReturnPacketSize(msg));
    printf(" Actual Packet size  = %d  \n", size);
    printf(" Virtual Packet size  = %d  \n\n",
                                      MESSAGE_ReturnVirtualPacketSize(msg));
    printf(" Original Message IP Header :-  \n");
    IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
    printf(" Source Address = %s  \n", srcAddr);
    IO_ConvertIpAddressToString(ipHeader->ip_dst, dstAddr);
    printf(" Destination Address = %s  \n", dstAddr);
    printf(" Identification Number = %d  \n", ipHeader->ip_id);
    printf(" Protocol = %d  \n", ipHeader->ip_p);
    printf(" TTL = %d  \n", ipHeader->ip_ttl);
    printf(" Fragment = %d  \n\n", ipHeader->ipFragment);
    msg->packet += ipHeaderSize;
    if (ipHeader->ip_p == IPPROTO_UDP)
    {
        printf(" Original Message UDP Header :-  \n");
        udpHeader = (TransportUdpHeader *) MESSAGE_ReturnPacket(msg);
        printf(" Source Port = %d  \n", udpHeader->sourcePort);
        printf(" Destination Port = %d  \n\n", udpHeader->destPort);
    }
    else if (ipHeader->ip_p == IPPROTO_TCP)
    {
        printf(" Original Message TCP Header :-  \n");
        tcpHeader = (tcphdr *) MESSAGE_ReturnPacket(msg);
        printf(" Source Port = %d  \n", tcpHeader->th_sport);
        printf(" Destination Port = %d  \n\n", tcpHeader->th_dport);
    }
    msg->packet -= ipHeaderSize;


#endif

    if (ipOption)
    {
        min = MIN(ICMP_MAX_ERROR_MESSAGE_SIZE - sizeof(IpHeaderType) -
                  ((sourceRoutelen + 1) * sizeof(NodeAddress)) -
                  sizeof(IcmpHeader),
                  size - ipHeaderSize + sizeof(IpHeaderType));
    }
    else
    {
        min = MIN(ICMP_MAX_ERROR_MESSAGE_SIZE - sizeof(IpHeaderType) -
                  sizeof(IcmpHeader),
                  size - ipHeaderSize + sizeof(IpHeaderType));
    }

    icmpPacket = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               NETWORK_PROTOCOL_ICMP,
                               MSG_NETWORK_IcmpData);

    MESSAGE_PacketAlloc(node,
                        icmpPacket,
                        min,
                        TRACE_ICMP);

    if (ipOption)
    {
        MESSAGE_AddVirtualPayload(node,
                              icmpPacket,
                              MIN(ICMP_MAX_ERROR_MESSAGE_SIZE -
                              sizeof(IpHeaderType) -
                              ((sourceRoutelen + 1) * sizeof(NodeAddress)) -
                              sizeof(IcmpHeader) -
                              MESSAGE_ReturnActualPacketSize(icmpPacket),
                              (UInt32)MESSAGE_ReturnVirtualPacketSize(msg)));
    }
    else
    {
        MESSAGE_AddVirtualPayload(node,
                              icmpPacket,
                              MIN(ICMP_MAX_ERROR_MESSAGE_SIZE -
                              sizeof(IpHeaderType) - sizeof(IcmpHeader) -
                              MESSAGE_ReturnActualPacketSize(icmpPacket),
                              (UInt32)MESSAGE_ReturnVirtualPacketSize(msg)));
    }

    origPacket = (char *)MESSAGE_ReturnPacket(msg);
    icmpData = (char *)MESSAGE_ReturnPacket(icmpPacket);


    memcpy(icmpData, origPacket, sizeof(IpHeaderType));
    char *icmpTemp = icmpData;
    char *origTemp = origPacket;
    icmpTemp = icmpTemp + sizeof(IpHeaderType);
    origTemp = origTemp + ipHeaderSize;
    memcpy(icmpTemp, origTemp, min - sizeof(IpHeaderType));

#ifdef DEBUG_ICMP_ERROR_MESSAGES
    IpHeaderType *ip;
    TransportUdpHeader* udp;
    tcphdr* tcp;
    ip = (IpHeaderType *) MESSAGE_ReturnPacket(icmpPacket);
    printf(" Generated Message IP Header :-  \n");
    IO_ConvertIpAddressToString(ip->ip_src, srcAddr);
    printf(" Source Address = %s  \n", srcAddr);
    IO_ConvertIpAddressToString(ip->ip_dst, dstAddr);
    printf(" Destination Address = %s  \n", dstAddr);
    printf(" Identification Number = %d  \n", ip->ip_id);
    printf(" Protocol = %d  \n", ip->ip_p);
    printf(" TTL = %d  \n", ip->ip_ttl);
    printf(" Fragment = %d  \n\n", ip->ipFragment);
    icmpPacket->packet += sizeof(IpHeaderType);
    if (ip->ip_p == IPPROTO_UDP)
    {
        udp = (TransportUdpHeader *) MESSAGE_ReturnPacket(icmpPacket);
        printf(" Generated Message UDP Header :-  \n");
        printf(" Source Port = %d  \n", udp->sourcePort);
        printf(" Destination Port = %d  \n\n", udp->destPort);
    }
    else if (ip->ip_p == IPPROTO_TCP)
    {
        tcp = (tcphdr *) MESSAGE_ReturnPacket(icmpPacket);
        printf(" Generated Message TCP Header :-  \n");
        printf(" Source Port = %d  \n", tcp->th_sport);
        printf(" Destination Port = %d  \n\n", tcp->th_dport);
    }
    icmpPacket->packet -= sizeof(IpHeaderType);
#endif

    MESSAGE_ExpandPacket(node, icmpPacket, sizeof(IcmpHeader));

    icmpHeader = (IcmpHeader*) MESSAGE_ReturnPacket(icmpPacket);

    memset(icmpHeader, 0, sizeof(IcmpHeader));

    NetworkIcmpSetIcmpHeader(node,
                             NULL,
                             icmpPacket,
                             icmpType,
                             icmpCode,
                             gatewayAddress,
                             pointer);

#ifdef DEBUG_ICMP_ERROR_MESSAGES
    printf("ICMP Packet Generated :-  \n");
    printf(" Packet size  = %d  \n", MESSAGE_ReturnPacketSize(icmpPacket));
    printf(" Actual Packet size  = %d  \n",
                                 MESSAGE_ReturnActualPacketSize(icmpPacket));
    printf(" Virtual Packet size  = %d  \n\n",
                                MESSAGE_ReturnVirtualPacketSize(icmpPacket));
    printf("ICMP Header :-  \n");
    printf(" ICMP Error Message Type = %d  \n", icmpHeader->icmpMessageType);
    printf(" ICMP Error Message Code = %d  \n", icmpHeader->icmpCode);
    printf(" ICMP Error Message Checksum = %d  \n",
                                                   icmpHeader->icmpCheckSum);
    printf(" ICMP Error Message pointer = %d  \n\n",
                                                 icmpHeader->Option.pointer);
#endif

    TosType priority = 0;

    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, icmpPacket, TRACE_NETWORK_LAYER,
              PACKET_OUT, &acnData);

    NetworkIcmpSendPacketToIp(node,
                              icmpPacket,
                              0,
                              interfaceId,
                              destinationAddress,
                              priority,
                              newSourceRoute,
                              sourceRoutelen,
                              NULL,
                              0,
                              NULL,
                              0,
                              immediateDestination);

    return TRUE;
}


/*
 * FUNCTION:   NetworkIcmpHandleTimestamp()
 * PURPOSE:    This function handles an ICMP Timestamp packet by initiating
 *             a TIMESTAMP REPLY.
 * RETURN:     None
 * ASSUMPTION: None
 * PARAMETERS: node,     node in which Icmp message will be created.
 *             msg, Timestamp packet received.
 *             sourceAddress, IP Address of the source of the Timestamp packet
 *             interfaceIndex, interface on which the packet was received
 */

void NetworkIcmpHandleTimestamp(Node *node,
                              Message *msg,
                              NodeAddress sourceAddress,
                              int interfaceIndex)
{

    unsigned short icmpType = ICMP_TIME_STAMP_REPLY;
    unsigned short icmpCode = 0;

    IpHeaderType *ipHeader;
    int size;
    Message *icmpPacket;
    char *icmpData;
    char *origPacket;
    char *transitTime;
    int interfaceId;
    char *newRecordRoute = NULL;
    char *newTimeStamp = NULL;
    NodeAddress *newSourceRoute = NULL;
    int recordRoutelen = 0;
    int sourceRoutelen = 0;
    int timeStamplen = 0;
    IcmpHeader *icmpHeader;
    short idNumber, sequenceNumber;
    clocktype now;
    int time;
    NodeAddress immediateDestination = 0;

    NetworkDataIp *ip = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;

    ipHeaderSizeInfo *ipHeaderSize = NULL;
    ipHeaderSize = (ipHeaderSizeInfo *)MESSAGE_ReturnInfo(msg,
                                                    INFO_TYPE_IpHeaderSize);
    msg->packet -= ipHeaderSize->size;
    ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

    if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst) ||
        ipHeader->ip_dst == ANY_DEST)
    {
        return;
    }

    for (interfaceId = 0; interfaceId < node->numberInterfaces;
         interfaceId++)
    {
        if (NetworkIpGetInterfaceBroadcastAddress(node,interfaceId)
                                                   == ipHeader->ip_dst)
        {
            return;
        }
    }
    if (IpHeaderSize(ipHeader) != sizeof(IpHeaderType))
    {
        IpOptionsHeaderType *sourceRouteOption =
                                  IpHeaderSourceRouteOptionField(ipHeader);
        IpOptionsHeaderType *recordRouteOption =
                                  IpHeaderRecordRouteOptionField(ipHeader);
        IpOptionsHeaderType *timeStampOption =
                                  IpHeaderTimestampOptionField(ipHeader);
        if (recordRouteOption)
        {
            recordRoutelen = recordRouteOption->len + 1;
            newRecordRoute = (char *)MEM_malloc(recordRoutelen);
            memset(newRecordRoute, 0, recordRoutelen);
            memcpy(newRecordRoute, (char *)recordRouteOption,
                                                             recordRoutelen);
        }
        if (timeStampOption)
        {
            timeStamplen = timeStampOption->len;
            newTimeStamp = (char *)MEM_malloc(timeStamplen);
            memset(newTimeStamp, 0, timeStamplen);
            memcpy(newTimeStamp, (char *)timeStampOption, timeStamplen);
        }
        if (sourceRouteOption)
        {
            NodeAddress *source = &sourceAddress;
            char *FirstAddress = ((char *) sourceRouteOption +
                                                sizeof(IpOptionsHeaderType));
            //move pointer back to obtain the next immediate destination to
            //be inserted in IP Header

            memcpy((char *)&immediateDestination,
                  (char *)sourceRouteOption + sourceRouteOption->ptr -
                  (sizeof(NodeAddress)) - 1, sizeof(NodeAddress));
            sourceRoutelen = (sourceRouteOption->len -
                              sizeof(IpOptionsHeaderType)) /
                              sizeof(NodeAddress);
            newSourceRoute = (NodeAddress *)
                            MEM_malloc(sourceRoutelen * sizeof(NodeAddress));
            memset(newSourceRoute, 0,
                                       sourceRoutelen * sizeof(NodeAddress));
            memcpy(newSourceRoute, source, sizeof(NodeAddress));
            source = newSourceRoute + 1;
            memcpy(source, FirstAddress,
                                 (sourceRoutelen - 1) * sizeof(NodeAddress));
            newSourceRoute = ReverseArray(newSourceRoute, sourceRoutelen);
        }
    }

    msg->packet += ipHeaderSize->size;
    icmpHeader = (IcmpHeader*)(msg->packet);
    idNumber = icmpHeader->Option.IcmpEchoTimeSecTrace.idNumber;
    sequenceNumber = icmpHeader->Option.IcmpEchoTimeSecTrace.sequenceNumber;
    MESSAGE_RemoveHeader(node,
                     msg,
                     sizeof(IcmpHeader),
                     TRACE_ICMP);

    icmpPacket = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               NETWORK_PROTOCOL_ICMP,
                               MSG_NETWORK_IcmpData);

    size = msg->packetSize;

    MESSAGE_PacketAlloc(node,
                        icmpPacket,
                        size,
                        TRACE_ICMP);

    origPacket = MESSAGE_ReturnPacket(msg);
    icmpData = MESSAGE_ReturnPacket(icmpPacket);
    memcpy(icmpData, origPacket, (int) size);
    transitTime = icmpData;
    transitTime = transitTime + 8;

    now = WallClock::getTrueRealTime();
    time = (int)now / MILLI_SECOND;
    memcpy(transitTime, &time, 4);

    MESSAGE_ExpandPacket(node, icmpPacket, sizeof(IcmpHeader));

    icmpHeader = (IcmpHeader*) MESSAGE_ReturnPacket(icmpPacket);

    memset(icmpHeader, 0, sizeof(IcmpHeader));

    NetworkIcmpSetIcmpHeader(node,
                             NULL,
                             icmpPacket,
                             icmpType,
                             icmpCode,
                             idNumber,
                             sequenceNumber);

    (icmp->icmpStat.icmpTimestampReplyGenerated)++;

    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, icmpPacket, TRACE_NETWORK_LAYER,
              PACKET_OUT, &acnData);

    NetworkIcmpSendPacketToIp(node,
                              icmpPacket,
                              0,
                              interfaceIndex,
                              sourceAddress,
                              0,
                              newSourceRoute,
                              sourceRoutelen,
                              newRecordRoute,
                              recordRoutelen,
                              newTimeStamp,
                              timeStamplen,
                              immediateDestination);


}

/*
 * FUNCTION:   NetworkIcmpGenerateTraceroute()
 * PURPOSE:    Create a ICMP Traceroute message and send it
 * RETURN:     None
 * ASSUMPTION: None
 * PARAMETERS: node,     node in which Icmp message will be created.
 *             msg,
 *             sourceAddress, IP Address of the source of the packet with
 *             Traceroute option in IP Header
 *             interfaceIndex, interface on which the packet was received
 */

void NetworkIcmpGenerateTraceroute (Node *node,
                  Message *msg,
                  NodeAddress sourceAddress,
                  int interfaceIndex)
{

    unsigned short icmpType = ICMP_TRACEROUTE;
    unsigned short icmpCode = 0;

    IpHeaderType *ipHeader;
    Message *icmpPacket;
    IcmpTraceRouteData *icmpData;
    unsigned short idNumber;
    IcmpHeader *icmpHeader;

    NetworkDataIp *ip = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
    ip_traceroute *ipOption = FindTraceRouteOption(ipHeader);

    icmpPacket = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               NETWORK_PROTOCOL_ICMP,
                               MSG_NETWORK_IcmpData);

    MESSAGE_PacketAlloc(node,
                       icmpPacket,
                       sizeof(IcmpTraceRouteData),
                       TRACE_ICMP);

    icmpData = (IcmpTraceRouteData*) icmpPacket->packet;

    memset(icmpData, 0, sizeof(IcmpTraceRouteData));

    icmpData->outboundHopCount = ipOption->outboundHopCount;
    icmpData->returnHopCount = 0;
    icmpData->outputLinkSpeed = 0;
    icmpData->outputLinkMTU = 0;
    idNumber = ipOption->idNumber;

    MESSAGE_ExpandPacket(node, icmpPacket, sizeof(IcmpHeader));

    icmpHeader = (IcmpHeader*) MESSAGE_ReturnPacket(icmpPacket);

    memset(icmpHeader, 0, sizeof(IcmpHeader));

    NetworkIcmpSetIcmpHeader(node,
                             NULL,
                             icmpPacket,
                             icmpType,
                             icmpCode,
                             idNumber,
                             0);

    (icmp->icmpStat.icmpTracerouteGenerated)++;

    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, icmpPacket, TRACE_NETWORK_LAYER,
              PACKET_OUT, &acnData);

    NetworkIcmpSendPacketToIp(node, icmpPacket, 0, interfaceIndex,
                             sourceAddress, 0, NULL, 0, NULL, 0, NULL, 0, 0);

}

/*
 * FUNCTION:   ReverseArray()
 * PURPOSE:    To reverse an array of NodeAddress type.
 * RETURN:     The pointer to the reversed array
 * ASSUMPTION: None
 * PARAMETERS: orig, pointer to the original array.
               size, size of the array.
 */

NodeAddress *ReverseArray(NodeAddress *orig, int size)
{
    unsigned short a = 0;
    NodeAddress swap = 0;

    for (; a < --size; a++) //increment a and decrement size until
                          //they meet eachother
    {
        swap = orig[a];       //put what's in a into swap space
        orig[a] = orig[size];    //put what's in size into a
        orig[size] = swap;       //put what's in the swap (a) into size
    }
    return orig;    //return the new (reversed) string (a pointer to it)
}

/*
 * FUNCTION:   NetworkIcmpRedirectIfApplicable
 * PURPOSE:    Redirects a packet if all of the checks are satisfied
 * RETURN:     NULL
 * PARAMETERS: node,              node that will send redirect
 *             msg,               message that causes redirect
 *             incomingInterface, interface that the message arrives on
 *             outgoingInterface, interface that the message leaves on
 *             nextHop,           the next hop destination of the message
 *             routeType,         host or network redirect
 */

void NetworkIcmpRedirectIfApplicable(Node* node, Message* msg,
                                     int incomingInterface,
                                     int outgoingInterface,
                                     NodeAddress nextHop, BOOL routeType)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    BOOL ICMPErrorMsgCreated;

    /*If ICMP isn't enabled or the next hop is unreachable,
    redirects do not apply*/

    if (ip->isIcmpEnable && nextHop != (unsigned int)NETWORK_UNREACHABLE)
    {
        NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;

        //Redirects should be enabled, the incoming interface and outgoing interface
        //should be the same, the redirect target should be in the same subnet, the
        //node should be an ICMP router, and there should be no source route
        //associated with the packet for redirects to apply

        if (icmp->redirectEnable && incomingInterface == outgoingInterface &&
            NetworkIpCheckIpAddressIsInSameSubnet
                    (node,outgoingInterface,ipHeader->ip_src)
            && icmp->router == TRUE && !(IpHeaderHasSourceRoute(ipHeader)))
        {
            RedirectCacheInfo* redirectCacheInfo = icmp->redirectCacheInfo;
            bool sendRedirect = true;

            /*checks to see if a redirect has already been sent for this
            particular source-destination pair in the last
            Redirect-Retry-Time.*/

            while (redirectCacheInfo != NULL)
            {
                if (redirectCacheInfo->ipSource == ipHeader->ip_src
                    && redirectCacheInfo->destination == ipHeader->ip_dst)
                {
                    sendRedirect = FALSE;
                    break;
                }
                redirectCacheInfo = redirectCacheInfo->next;
            }

            /*redirects should not be sent for packets originating
            at that node.*/

            if (NetworkIpIsMyIP(node, ipHeader->ip_src))
            {
                sendRedirect = FALSE;
            }

#ifdef ICMP_DEBUG
            {
                 char clockStr[100];
                 ctoa(node->getNodeTime(), clockStr);

                 printf("ipHeader->ip_src = %X, ipHeader->ip_dst = %X,",
                     ipHeader->ip_src, ipHeader->ip_dst);
                 printf("outgoingInterface = %i, incomingInterface = %i,",
                     outgoingInterface, incomingInterface);
                 printf("ip->isIcmpEnable = %i, icmp->router = %i,"
                        " nextHop = %u,",ip->isIcmpEnable, icmp->router,
                                                                   nextHop);
                 printf("routeType = %i, sendRedirect = %i,",
                     routeType, sendRedirect);
                 printf("clockStr = %s\n", clockStr);
            }
#endif

            if (sendRedirect)
            {


                // Send ICMP redirect Message
                NetworkIcmpUpdateRedirectCache(node,
                                               ipHeader->ip_src,
                                               ipHeader->ip_dst);

                if (nextHop == 0)
                {
                    ICMPErrorMsgCreated =
                        NetworkIcmpCreateErrorMessage(node,
                              msg,
                              ipHeader->ip_src,
                              incomingInterface,
                              ICMP_REDIRECT,
                              1,
                              0,
                              ipHeader->ip_dst);
                }
                else
                {
                    ICMPErrorMsgCreated =
                        NetworkIcmpCreateErrorMessage(node,
                              msg,
                              ipHeader->ip_src,
                              incomingInterface,
                              ICMP_REDIRECT,
                              1,
                              0,
                              nextHop);
                }


                if (ICMPErrorMsgCreated)
                {
#ifdef DEBUG
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHeader->ip_src, srcAddr);
                    printf("Node %d sending redirect message to %s\n",
                                        node->nodeId, srcAddr);
#endif
                    (icmp->icmpErrorStat.icmpRedirctGenerate)++;
                }


            }
        }
    }
}

/*
 * FUNCTION:   NetworkIcmpCreateSecurityErrorMessage
 * PURPOSE:    Create a ICMP Security Error message and send it
 * RETURN:     None
 * PARAMETERS: node,              node that will send redirect
 *             msg,               message that causes redirect
 *             incomingInterface, interface that the message arrives on
 */

void NetworkIcmpCreateSecurityErrorMessage( Node* node,
                                           Message* msg,
                                           int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;
    BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                            msg,
                                            ipHdr->ip_src,
                                            incomingInterface,
                                            ICMP_SECURITY_FAILURES,
                                            ICMP_AUTHENICATION_FAILED,
                                            0,
                                            0);
    if (ICMPErrorMsgCreated) {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
        char srcAddr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(ipHdr->ip_src, srcAddr);
        printf("Node %d sending security failed message to %s\n",
                            node->nodeId, srcAddr);
#endif
        (icmp->icmpErrorStat.icmpSecurityFailedSent)++;
     }
 }


