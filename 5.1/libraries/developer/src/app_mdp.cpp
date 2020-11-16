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
#include "main.h"

#include "network_ip.h"
#include "ipv6.h"
#include "app_mdp.h"
#include "external_socket.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

//this macro is declared in file 'mdpProtoDefs.h'
//#define MDP_DEBUG 0


/*
 * NAME:        MdpGetAppTypeForServer.
 * PURPOSE:     finding app type for receiver node of the application
 * PARAMETERS:  appType - app type for sender node
 * RETURN:      AppType.
 */
AppType MdpGetAppTypeForServer(AppType appType)
{
    switch (appType)
    {
        case APP_CBR_CLIENT:
        case APP_CBR_SERVER:
        {
            return APP_CBR_SERVER;
        }
        case APP_VBR_CLIENT:
        case APP_VBR_SERVER:
        {
            return APP_VBR_SERVER;
        }
        case APP_MCBR_CLIENT:
        case APP_MCBR_SERVER:
        {
            return APP_MCBR_SERVER;
        }
        case APP_TRAFFIC_GEN_CLIENT:
        case APP_TRAFFIC_GEN_SERVER:
        {
            return APP_TRAFFIC_GEN_SERVER;
        }
        case APP_TRAFFIC_TRACE_CLIENT:
        case APP_TRAFFIC_TRACE_SERVER:
        {
            return APP_TRAFFIC_TRACE_SERVER;
        }
        case APP_SUPERAPPLICATION_CLIENT:
        {
            return APP_SUPERAPPLICATION_SERVER;
        }
        case APP_SUPERAPPLICATION_SERVER:
        {
            return APP_SUPERAPPLICATION_CLIENT;
        }
        case APP_FORWARD:
        {
            return APP_FORWARD;
        }
#ifdef JNE_LIB
        case APP_JNE_JWNM:
        {
            return APP_JNE_CONFIGURATION_AGENT;
        }
        case APP_JNE_CONFIGURATION_AGENT:
        {
            return APP_JNE_CONFIGURATION_AGENT;
        }
#endif
        default:
        {
            return appType;
        }
    }
}


/*
 * NAME:        MdpGetAppTypeForClient.
 * PURPOSE:     finding app type for sender node of the application
 * PARAMETERS:  appType - app type for receiver node
 * RETURN:      AppType.
 */
AppType MdpGetAppTypeForClient(AppType appType)
{
    switch (appType)
    {
        case APP_CBR_SERVER:
        case APP_CBR_CLIENT:
        {
            return APP_CBR_CLIENT;
        }
        case APP_VBR_SERVER:
        case APP_VBR_CLIENT:
        {
            return APP_VBR_CLIENT;
        }
        case APP_MCBR_SERVER:
        case APP_MCBR_CLIENT:
        {
            return APP_MCBR_CLIENT;
        }
        case APP_TRAFFIC_GEN_SERVER:
        case APP_TRAFFIC_GEN_CLIENT:
        {
            return APP_TRAFFIC_GEN_CLIENT;
        }
        case APP_TRAFFIC_TRACE_SERVER:
        case APP_TRAFFIC_TRACE_CLIENT:
        {
            return APP_TRAFFIC_TRACE_CLIENT;
        }
        case APP_SUPERAPPLICATION_SERVER:
        {
            return APP_SUPERAPPLICATION_CLIENT;
        }
        case APP_SUPERAPPLICATION_CLIENT:
        {
            return APP_SUPERAPPLICATION_SERVER;
        }
        case APP_FORWARD:
        {
            return APP_FORWARD;
        }
#ifdef JNE_LIB
        case APP_JNE_JWNM:
        {
            return APP_JNE_CONFIGURATION_AGENT;
        }
        case APP_JNE_CONFIGURATION_AGENT:
        {
            return APP_JNE_CONFIGURATION_AGENT;
        }
#endif
        default:
        {
            return appType;
        }
    }
}



/*
 * NAME:        MdpGetTraceProtocolForAppType.
 * PURPOSE:     finding TraceProtocolType for the called appType
 * PARAMETERS:  appType - app type for receiver node
 * RETURN:      TraceProtocolType.
 */
TraceProtocolType MdpGetTraceProtocolForAppType(AppType appType)
{
    switch (appType)
    {
        case APP_CBR_SERVER:
        {
            return TRACE_CBR;
        }
        case APP_VBR_SERVER:
        {
            return TRACE_VBR;
        }
        case APP_MCBR_SERVER:
        {
            return TRACE_MCBR;
        }
        case APP_TRAFFIC_GEN_SERVER:
        {
            return TRACE_TRAFFIC_GEN;
        }
        case APP_TRAFFIC_TRACE_SERVER:
        {
            return TRACE_TRAFFIC_TRACE;
        }
        case APP_SUPERAPPLICATION_SERVER:
        {
            return TRACE_SUPERAPPLICATION;
        }
        case APP_SUPERAPPLICATION_CLIENT:
        {
            return TRACE_SUPERAPPLICATION;
        }
        case APP_FORWARD:
        {
            return TRACE_FORWARD;
        }
        case APP_NETCONF_AGENT:
        {
            return TRACE_NETCONF_AGENT;
        }
#ifdef JNE_LIB
        case APP_JNE_JWNM:
        {
            return TRACE_JNE_JWNM;
        }
        case APP_JNE_CONFIGURATION_AGENT:
        {
            return TRACE_JNE_CONFIGURATION_AGENT;
        }
#endif
        default:
        {
            return TRACE_UNDEFINED;
        }
    }
}


/*
 * NAME:        MdpIsMulticastAddress.
 * PURPOSE:     verify multicast address
 * PARAMETERS:  node - pointer to the node.
 *              address - address that needs to verify.
 * RETURN:      BOOL.
 */
BOOL MdpIsMulticastAddress(Node* node, Address* addr)
{
    BOOL isMulticast = FALSE;

    if (addr->networkType == NETWORK_IPV4)
    {
        isMulticast = NetworkIpIsMulticastAddress(
                                node,
                                addr->interfaceAddr.ipv4);
    }
    else if (addr->networkType == NETWORK_IPV6)
    {
        isMulticast = IS_MULTIADDR6(addr->interfaceAddr.ipv6);
    }

    return isMulticast;
}

/*
 * NAME:        MdpInitOptParamWithDefaultValues.
 * PURPOSE:     Init common parameters with default value
 * PARAMETERS:  node - pointer to the node which received the message.
 *              mdpCommonData - pointer to struct MdpCommonParameters
 *              nodeInput - A pointer to NodeInput with default value NULL
 * RETURN:      none.
 */
void MdpInitOptParamWithDefaultValues(Node* node,
                                     MdpCommonParameters* mdpCommonData,
                                     const NodeInput* nodeInput)
{
    char tempStr[MAX_STRING_LENGTH];

    mdpCommonData->tos = APP_DEFAULT_TOS;
    mdpCommonData->txRate = MDP_DEFAULT_TX_RATE;
    mdpCommonData->ttlCount = MDP_DEFAULT_TTL;

    sprintf(tempStr, "%lfS", MDP_DEFAULT_GRTT_ESTIMATE);
    mdpCommonData->initialGrtt = atof(tempStr); //need to change in double

    mdpCommonData->segmentSize = MDP_DEFAULT_SEGMENT_SIZE;
    mdpCommonData->blockSize = MDP_DEFAULT_BLOCK_SIZE;
    mdpCommonData->numParity = MDP_DEFAULT_NPARITY;
    mdpCommonData->numAutoParity = MDP_DEFAULT_NUM_AUTO_PARITY;
    mdpCommonData->emconEnabled = MDP_DEFAULT_EMCON_ENABLED;
    mdpCommonData->loopbackEnabled = MDP_DEFAULT_LOOPBACK_ENABLED;

    mdpCommonData->reportMsgEnabled = MDP_DEFAULT_REPORT_MESSAGES_ENABLED;
    mdpCommonData->unicastNackEnabled = MDP_DEFAULT_UNICAST_NACK_ENABLED;
    mdpCommonData->multicastAckEnabled = MDP_DEFAULT_MULTICAST_ACK_ENABLED;
    mdpCommonData->positiveAckEnabled = MDP_DEFAULT_POSITIVE_ACK_WITH_REPORT;

    mdpCommonData->baseObjectId = MDP_DEFAULT_BASE_OBJECT_ID;
    mdpCommonData->archiveModeEnabled = MDP_DEFAULT_ARCHIVE_MODE_ENABLED;
    mdpCommonData->archivePath = MDP_DEFAULT_ARCHIVE_PATH;
    mdpCommonData->streamIntegrityEnabled =
                                        MDP_DEFAULT_STREAM_INTEGRITY_ENABLED;
    mdpCommonData->flowControlEnabled = MDP_DEFAULT_FLOW_CONTROL_ENABLED;
    mdpCommonData->flowControlTxRateMin =
                                        MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MIN;
    mdpCommonData->flowControlTxRateMax =
                                        MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MAX;
    mdpCommonData->txCacheCountMin = MDP_DEFAULT_TX_CACHE_COUNT_MIN;
    mdpCommonData->txCacheCountMax = MDP_DEFAULT_TX_CACHE_COUNT_MAX;
    mdpCommonData->txCacheSizeMax = MDP_DEFAULT_TX_CACHE_SIZE_MAX;
    mdpCommonData->txBufferSize = MDP_DEFAULT_BUFFER_SIZE;
    mdpCommonData->rxBufferSize = MDP_DEFAULT_BUFFER_SIZE;
    mdpCommonData->segmentPoolDepth = MDP_DEFAULT_SEGMENT_POOL_DEPTH;

    mdpCommonData->robustFactor = MDP_DEFAULT_ROBUSTNESS;

    if (nodeInput)
    {
        BOOL wasFound = FALSE;
        BOOL retValue = FALSE;
        char* token = NULL;
        char* next = NULL;
        char delims[] = {" ,\t"};
        char iotoken[MAX_STRING_LENGTH];
        char buf[MAX_STRING_LENGTH] = {0};
        char errStr[MAX_STRING_LENGTH];

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "MDP-TX-CACHE",
            &retValue,
            buf);

        if (retValue)
        {
            // for minCount
            token = IO_GetDelimitedToken(iotoken, buf, delims, &next);
            if (!token)
            {
                sprintf(errStr, "No value defined for MDP-TX-CACHE "
                                "'min-count' in config file. Continue with "
                                "the default value: %d. \n",
                                MDP_DEFAULT_TX_CACHE_COUNT_MIN);
                ERROR_ReportWarning(errStr);

                wasFound = FALSE;
            }
            else if (!IO_IsStringNonNegativeInteger(token))
            {
                sprintf(errStr, "Invalid value %s for MDP-TX-CACHE "
                                "'min-count' in config file. Continue with "
                                "the default value: %d. \n",
                               token, MDP_DEFAULT_TX_CACHE_COUNT_MIN);
                ERROR_ReportWarning(errStr);
                wasFound = TRUE;
            }
            else
            {
                mdpCommonData->txCacheCountMin = atoi(token);
                wasFound = TRUE;
            }

            if (wasFound)
            {
                // for maxCount
                token = IO_GetDelimitedToken(iotoken, next, delims, &next);
                if (!token)
                {
                    sprintf(errStr,"No value defined for MDP-TX-CACHE "
                            "'max-count' in config file. Continue with the "
                            "default value: %d. \n",
                            MDP_DEFAULT_TX_CACHE_COUNT_MAX);
                    ERROR_ReportWarning(errStr);

                    wasFound = FALSE;
                }
                else if (!IO_IsStringNonNegativeInteger(token))
                {
                    sprintf(errStr, "Invalid value %s for MDP-TX-CACHE "
                                "'max-count' in config file. Continue with "
                                "the default value: %d. \n",
                                token, MDP_DEFAULT_TX_CACHE_COUNT_MAX);
                    ERROR_ReportWarning(errStr);
                    wasFound = TRUE;
                }
                else
                {
                    mdpCommonData->txCacheCountMax = atoi(token);
                    wasFound = TRUE;
                }
            }

            if (wasFound)
            {
                // for maxSize
                token = IO_GetDelimitedToken(iotoken, next, delims, &next);
                if (!token)
                {
                    sprintf(errStr,"No value defined for MDP-TX-CACHE "
                            "'max-size' in config file. Continue with the "
                            "default value: %d. \n",
                            MDP_DEFAULT_TX_CACHE_SIZE_MAX);
                    ERROR_ReportWarning(errStr);

                    wasFound = FALSE;
                }
                else if (!IO_IsStringNonNegativeInteger(token))
                {
                    sprintf(errStr, "Invalid value %s for MDP-TX-CACHE "
                                "'max-size' in config file. Continue with "
                                "the default value: %d. \n",
                                token, MDP_DEFAULT_TX_CACHE_SIZE_MAX);
                    ERROR_ReportWarning(errStr);
                    wasFound = TRUE;
                }
                else
                {
                    mdpCommonData->txCacheSizeMax = atoi(token);
                    wasFound = TRUE;
                }
            }
        }// retValue for MDP-TX-CACHE

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "MDP-TX-BUFFER-SIZE",
            &retValue,
            buf);

        if (retValue)
        {
            if (IO_IsStringNonNegativeInteger(buf))
            {
                sscanf(buf, "%u", &mdpCommonData->txBufferSize);
            }
            else
            {
                sprintf(errStr, "Invalid value %s for MDP-TX-BUFFER-SIZE in "
                                "config file. Continue with the default "
                                "value: %u. \n",
                                buf, MDP_DEFAULT_BUFFER_SIZE);
                ERROR_ReportWarning(errStr);
            }
        }

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "MDP-RX-BUFFER-SIZE",
            &retValue,
            buf);

        if (retValue)
        {
            if (IO_IsStringNonNegativeInteger(buf))
            {
                sscanf(buf, "%u", &mdpCommonData->rxBufferSize);
            }
            else
            {
                sprintf(errStr, "Invalid value %s for MDP-RX-BUFFER-SIZE in "
                                "config file. Continue with the default "
                                "value: %u. \n",
                                buf, MDP_DEFAULT_BUFFER_SIZE);
                ERROR_ReportWarning(errStr);
            }
        }

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "MDP-SEGMENT-POOL-SIZE",
            &retValue,
            buf);

        if (retValue)
        {
            if (IO_IsStringNonNegativeInteger(buf))
            {
                sscanf(buf, "%d", &mdpCommonData->segmentPoolDepth);
            }
            else
            {
                sprintf(errStr, "Invalid value %s for MDP-SEGMENT-POOL-SIZE "
                                "in config file. Continue with the default "
                                "value: %u. \n",
                                buf, MDP_DEFAULT_SEGMENT_POOL_DEPTH);
                ERROR_ReportWarning(errStr);
            }
        }
    }// if (nodeInput)
}



/*
 * NAME:        MdpInitializeOptionalParameters.
 * PURPOSE:     Init parameters with user defined value
 * PARAMETERS:  node - pointer to the node which received the message.
 *              optionTokens - pointer to configuration string
 *              mdpCommonData - pointer to struct MdpCommonParameters
 * RETURN:      none.
 */
void MdpInitializeOptionalParameters(Node* node,
                                     char* optionTokens,
                                     MdpCommonParameters* mdpCommonData)
{
    char* token = NULL;
    char* next = NULL;
    char delims[] = {" ,\t"};
    char iotoken[MAX_STRING_LENGTH];
    char errStr[MAX_STRING_LENGTH];

    token = IO_GetDelimitedToken(iotoken, optionTokens, delims, &next);

    while (token)
    {
        if (strcmp(token,"TOS")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->tos = APP_DEFAULT_TOS;
            }
            else
            {
                unsigned value = (unsigned) atoi(token);

                if (!IO_IsStringNonNegativeInteger(token)
                    || value > 255)
                {
                    sprintf(errStr, "Invalid value %s for TOS. "
                                   "TOS value range 0 to 255. "
                                   "Continue with the default value: %d. \n",
                                   token, APP_DEFAULT_TOS);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->tos = APP_DEFAULT_TOS;
                }
                else
                {
                    // Equivalent TOS [8-bit] value
                    mdpCommonData->tos = value;
                }
            }
        }// if (strcmp(token,"TOS")== 0)
        else if (strcmp(token,"TX-RATE")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->txRate = MDP_DEFAULT_TX_RATE;
            }
            else
            {
                if (IO_IsStringNonNegativeInteger(token))
                {
                    mdpCommonData->txRate = atoi(token);
                }
                else
                {
                    sprintf(errStr, "Invalid value %s for MDP-TX-RATE. "
                                   "Continue with the default value: %d. \n",
                                   token, MDP_DEFAULT_TX_RATE);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->txRate = MDP_DEFAULT_TX_RATE;
                }
            }
        }// else if (strcmp(token,"TX-RATE")== 0)
        else if (strcmp(token,"TTL-COUNT")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->ttlCount = MDP_DEFAULT_TTL;
            }
            else
            {
                mdpCommonData->ttlCount = atoi(token);

                if (!IO_IsStringNonNegativeInteger(token)
                    || mdpCommonData->ttlCount > 255)
                {
                    sprintf(errStr,"Invalid value %s for TTL-COUNT. "
                                   "Range is 0 to 255. "
                                   "Continue with the default value: %d. \n",
                                   token, MDP_DEFAULT_TTL);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->ttlCount = MDP_DEFAULT_TTL;
                }
            }
        }// else if (strcmp(token,"TTL-COUNT")== 0)
        else if (strcmp(token,"INITIAL-GRTT")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            double defaultValue = MDP_DEFAULT_GRTT_ESTIMATE;

            if (!token)
            {
                mdpCommonData->initialGrtt = defaultValue;
            }
            else
            {
                mdpCommonData->initialGrtt = atof(token);

                double minRange = 0.0001;
                double maxRange = 15;

                if (mdpCommonData->initialGrtt < minRange
                    || mdpCommonData->initialGrtt > maxRange)
                {
                    sprintf(errStr,"Invalid value %s for INITIAL-GRTT. "
                               "Range is 0.0001 to 15 seconds. "
                               "Continue with the default value: %1.1lf. \n",
                               token, MDP_DEFAULT_GRTT_ESTIMATE);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->initialGrtt = defaultValue;
                }
            }
        }// else if (strcmp(token,"INITIAL-GRTT")== 0)
        else if (strcmp(token,"SEGMENT-SIZE")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->segmentSize = MDP_DEFAULT_SEGMENT_SIZE;
            }
            else
            {
                mdpCommonData->segmentSize = atoi(token);

                if (!IO_IsStringNonNegativeInteger(token)
                    || mdpCommonData->segmentSize < 64
                    || mdpCommonData->segmentSize > 8128)
                {
                    sprintf(errStr,"Invalid value %s for SEGMENT-SIZE. "
                                  "Range is 64 to 8128. "
                                  "Continue with the default value: %d. \n",
                                  token, MDP_DEFAULT_SEGMENT_SIZE);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->segmentSize = MDP_DEFAULT_SEGMENT_SIZE;
                }
            }
        }// else if (strcmp(token,"SEGMENT-SIZE")== 0)
        else if (strcmp(token,"BLOCK-SIZE")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->blockSize = MDP_DEFAULT_BLOCK_SIZE;
            }
            else
            {
                Int32 size = atoi(token);

                if (!IO_IsStringNonNegativeInteger(token)
                    || size < 1 || size > 255)
                {
                    sprintf(errStr,"Invalid value %s for BLOCK-SIZE. "
                                   "Range is 1 to 255. "
                                   "Continue with the default value: %d. \n",
                                   token, MDP_DEFAULT_BLOCK_SIZE);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->blockSize = MDP_DEFAULT_BLOCK_SIZE;
                }
                else
                {
                    mdpCommonData->blockSize = (unsigned char)size;
                }
            }
        }// else if (strcmp(token,"BLOCK-SIZE")== 0)
        else if (strcmp(token,"NUM-PARITY")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->numParity = MDP_DEFAULT_NPARITY;
            }
            else
            {
                Int32 count = atoi(token);

                if (!IO_IsStringNonNegativeInteger(token)
                    ||count < 0 || count > 128
                    || ((mdpCommonData->blockSize + count) > 255))
                {
                    sprintf(errStr,"Invalid value %s for NUM-PARITY. "
                               "Range is 0 to 128 "
                               "so that (<blockSize> + <numParity>) <= 255. "
                               "Continue with the default value: %d. \n",
                               token, MDP_DEFAULT_NPARITY);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->numParity = MDP_DEFAULT_NPARITY;
                }
                else
                {
                    mdpCommonData->numParity = (unsigned char)count;
                }
            }
        }// else if (strcmp(token,"NUM-PARITY")== 0)
        else if (strcmp(token,"NUM-AUTO-PARITY")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->numAutoParity = MDP_DEFAULT_NUM_AUTO_PARITY;
            }
            else
            {
                Int32 count = atoi(token);

                if (!IO_IsStringNonNegativeInteger(token)
                    || count < 0 || count > 128
                    || (count > mdpCommonData->numParity))
                {
                    sprintf(errStr, "Invalid value %s for NUM-AUTO-PARITY. "
                                    "Range is 0 to 128 "
                                    "so that (autoParity <= numParity). "
                                   "Continue with the default value: %d. \n",
                                   token, MDP_DEFAULT_NUM_AUTO_PARITY);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->numAutoParity =
                                                 MDP_DEFAULT_NUM_AUTO_PARITY;
                }
                else
                {
                    mdpCommonData->numAutoParity = (unsigned char)count;
                }
            }
        }// else if (strcmp(token,"NUM-AUTO-PARITY")== 0)
        else if (strcmp(token,"EMCON-ENABLED")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->emconEnabled = MDP_DEFAULT_EMCON_ENABLED;
            }
            else
            {
                if (strcmp(token, "NO") == 0)
                {
                    mdpCommonData->emconEnabled = FALSE;
                }
                else if (strcmp(token, "YES") == 0)
                {
                    mdpCommonData->emconEnabled = TRUE;
                }
                else
                {
                    sprintf(errStr, "Invalid value %s for EMCON-ENABLED. "
                                  "Continue with the default value: NO. \n",
                                   token);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->emconEnabled = MDP_DEFAULT_EMCON_ENABLED;
                }
            }
        }// else if (strcmp(token,"EMCON-ENABLED")== 0)
        else if (strcmp(token,"LOOPBACK-ENABLED")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->loopbackEnabled = MDP_DEFAULT_LOOPBACK_ENABLED;
            }
            else
            {
                if (strcmp(token, "NO") == 0)
                {
                    mdpCommonData->loopbackEnabled = FALSE;
                }
                else if (strcmp(token, "YES") == 0)
                {
                    mdpCommonData->loopbackEnabled = TRUE;
                }
                else
                {
                    sprintf(errStr, "Invalid value %s for LOOPBACK-ENABLED. "
                                  "Continue with the value: %s. \n",
                                   token,
                            (mdpCommonData->loopbackEnabled ? "YES" : "NO"));

                    ERROR_ReportWarning(errStr);
                }
            }

            if (mdpCommonData->loopbackEnabled
                && !NetworkIpIsLoopbackEnabled(node))
            {
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr,"IP Loopback is disabled. Hence enabling "
                               "MDP loopback will not have any impact "
                               "on node %d. \n", node->nodeId);
                ERROR_ReportWarning(errStr);
            }
        }// else if (strcmp(token,"LOOPBACK-ENABLED")== 0)
        else if (strcmp(token,"REPORT-MESSAGES-ENABLED")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->reportMsgEnabled =
                                         MDP_DEFAULT_REPORT_MESSAGES_ENABLED;
            }
            else
            {
                if (strcmp(token, "NO") == 0)
                {
                    mdpCommonData->reportMsgEnabled = FALSE;
                }
                else if (strcmp(token, "YES") == 0)
                {
                    mdpCommonData->reportMsgEnabled = TRUE;
                }
                else
                {
                    sprintf(errStr,"Invalid value %s for "
                                   "REPORT-MESSAGES-ENABLED. "
                                  "Continue with the default value: NO. \n",
                                 token);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->reportMsgEnabled =
                                         MDP_DEFAULT_REPORT_MESSAGES_ENABLED;
                }
            }
        }// else if (strcmp(token,"REPORT-MESSAGES-ENABLED")== 0)
        else if (strcmp(token,"UNICAST-NACK-ENABLED")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->unicastNackEnabled =
                                            MDP_DEFAULT_UNICAST_NACK_ENABLED;
            }
            else
            {
                if (strcmp(token, "NO") == 0)
                {
                    mdpCommonData->unicastNackEnabled = FALSE;
                }
                else if (strcmp(token, "YES") == 0)
                {
                    mdpCommonData->unicastNackEnabled = TRUE;
                }
                else
                {
                    sprintf(errStr, "Invalid value %s for "
                                  "UNICAST-NACK-ENABLED. Continue "
                                  "with the default value: NO. \n",
                                  token);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->unicastNackEnabled =
                                            MDP_DEFAULT_UNICAST_NACK_ENABLED;
                }
            }
        }// else if (strcmp(token,"UNICAST-NACK-ENABLED")== 0)
        else if (strcmp(token,"MULTICAST-ACK-ENABLED")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->multicastAckEnabled =
                                           MDP_DEFAULT_MULTICAST_ACK_ENABLED;
            }
            else
            {
                if (strcmp(token, "NO") == 0)
                {
                    mdpCommonData->multicastAckEnabled = FALSE;
                }
                else if (strcmp(token, "YES") == 0)
                {
                    mdpCommonData->multicastAckEnabled = TRUE;
                }
                else
                {
                    sprintf(errStr,"Invalid value %s for "
                                   "MULTICAST-ACK-ENABLED. "
                                  "Continue with the default value: NO. \n",
                                  token);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->multicastAckEnabled =
                                           MDP_DEFAULT_MULTICAST_ACK_ENABLED;
                }
            }
        }// else if (strcmp(token,"MULTICAST-ACK-ENABLED")== 0)
        else if (strcmp(token,"POSITIVE-ACK-WITH-REPORT")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->positiveAckEnabled =
                                        MDP_DEFAULT_POSITIVE_ACK_WITH_REPORT;
            }
            else
            {
                if (strcmp(token, "NO") == 0)
                {
                    mdpCommonData->positiveAckEnabled = FALSE;
                }
                else if (strcmp(token, "YES") == 0)
                {
                    mdpCommonData->positiveAckEnabled = TRUE;
                }
                else
                {
                    sprintf(errStr,"Invalid value %s for "
                                   "POSITIVE-ACK-WITH-REPORT. Continue with "
                                  "the default value: NO. \n", token);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->positiveAckEnabled =
                                        MDP_DEFAULT_POSITIVE_ACK_WITH_REPORT;
                }
            }
        }// else if (strcmp(token,"POSITIVE-ACK-WITH-REPORT")== 0)
        else if (strcmp(token,"POSITIVE-ACK-NODES")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            NodeAddress addr;
            while (token)
            {
                if (IO_IsStringNonNegativeInteger(token))
                {
                    mdpCommonData->ackList->push_back((UInt32)atoi(token));

                    token = IO_GetDelimitedToken(iotoken,next,delims,&next);
                    continue;
                }

                IO_ConvertStringToNodeAddress(token, &addr);

                mdpCommonData->ackList->push_back((UInt32)addr);

                token = IO_GetDelimitedToken(iotoken,next,delims,&next);
            }
        }// else if (strcmp(token,"POSITIVE-ACK-NODES")== 0)
        else if (strcmp(token,"BASE-OBJECT-ID")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->baseObjectId = MDP_DEFAULT_BASE_OBJECT_ID;
            }
            else
            {
                if (!IO_IsStringNonNegativeInteger(token))
                {
                    sprintf(errStr, "Invalid value %s for BASE-OBJECT-ID. "
                                 "Continue with the default value: %d. \n",
                                 token, MDP_DEFAULT_BASE_OBJECT_ID);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->baseObjectId = MDP_DEFAULT_BASE_OBJECT_ID;
                }
                else
                {
                    sscanf(token, "%u", &mdpCommonData->baseObjectId);
                }
            }
        }// else if (strcmp(token,"BASE-OBJECT-ID")== 0)
        else if (strcmp(token,"ARCHIVE-MODE-ENABLED")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->archiveModeEnabled =
                                            MDP_DEFAULT_ARCHIVE_MODE_ENABLED;
            }
            else
            {
                if (strcmp(token, "NO") == 0)
                {
                    mdpCommonData->archiveModeEnabled = FALSE;
                }
                else if (strcmp(token, "YES") == 0)
                {
                    mdpCommonData->archiveModeEnabled = TRUE;
            }
                else
                {
                    sprintf(errStr,"Invalid value %s for "
                                   "ARCHIVE-MODE-ENABLED. "
                                   "Continue with the default value: NO.\n",
                                   token);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->archiveModeEnabled =
                                            MDP_DEFAULT_ARCHIVE_MODE_ENABLED;
                }
            }
        }// else if (strcmp(token,"ARCHIVE-MODE-ENABLED")== 0)
        else if (strcmp(token,"ARCHIVE-PATH")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->archivePath = MDP_DEFAULT_ARCHIVE_PATH;
                sprintf(errStr,"Invalid value %s for "
                               "ARCHIVE-PATH. "
                               "Continue with the default location: "
                               "Current Dir.\n",
                               token);
                ERROR_ReportWarning(errStr);
            }
            else
            {
                Int32 pathLen = strlen(token);
                mdpCommonData->archivePath = (char*) MEM_malloc(pathLen + 1);
                memset(mdpCommonData->archivePath, 0, pathLen+1);
                memcpy(mdpCommonData->archivePath, token, pathLen);
            }
        }// else if (strcmp(token,"ARCHIVE-PATH")== 0)
        else if (strcmp(token,"STREAM-INTEGRITY-ENABLED")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->streamIntegrityEnabled =
                                        MDP_DEFAULT_STREAM_INTEGRITY_ENABLED;
            }
            else
            {
                if (strcmp(token, "NO") == 0)
                {
                    mdpCommonData->streamIntegrityEnabled = FALSE;
                }
                else if (strcmp(token, "YES") == 0)
                {
                    mdpCommonData->streamIntegrityEnabled = TRUE;
                }
                else
                {
                    sprintf(errStr,"Invalid value %s for "
                                   "STREAM-INTEGRITY-ENABLED. "
                                   "Continue with the default value: YES.\n",
                                   token);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->streamIntegrityEnabled =
                                        MDP_DEFAULT_STREAM_INTEGRITY_ENABLED;
                }
            }
        }// else if (strcmp(token,"STREAM-INTEGRITY-ENABLED")== 0)
        else if (strcmp(token,"FLOW-CONTROL-ENABLED")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->flowControlEnabled =
                                            MDP_DEFAULT_FLOW_CONTROL_ENABLED;
            }
            else
            {
                if (strcmp(token, "NO") == 0)
                {
                    mdpCommonData->flowControlEnabled = FALSE;
                }
                else if (strcmp(token, "YES") == 0)
                {
                    mdpCommonData->flowControlEnabled = TRUE;
                }
                else
                {
                   sprintf(errStr,"Invalid value %s for FLOW-CONTROL-ENABLED"
                                ". Continue with the default value: NO. \n",
                                 token);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->flowControlEnabled =
                                            MDP_DEFAULT_FLOW_CONTROL_ENABLED;
                }
            }
        }// else if (strcmp(token,"FLOW-CONTROL-ENABLED")== 0)
        else if (strcmp(token,"FLOW-CONTROL-TX-RATE")== 0)
        {
            // for minValue
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->flowControlTxRateMin =
                                        MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MIN;
            }
            else
            {
                mdpCommonData->flowControlTxRateMin = atoi(token);

                if (!IO_IsStringNonNegativeInteger(token))
                {
                    sprintf(errStr, "Invalid value found %s for the "
                                "'min-value' of FLOW-CONTROL-TX-RATE. "
                                "Continue with default value: %d. \n",
                                token, MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MIN);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->flowControlTxRateMin =
                                        MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MIN;
                }
            }

            if (token)
            {
            // for maxValue
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);
            }

            if (!token)
            {
                mdpCommonData->flowControlTxRateMax =
                                        MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MAX;
            }
            else
            {
                mdpCommonData->flowControlTxRateMax = atoi(token);
                if (!IO_IsStringNonNegativeInteger(token))
                {
                    sprintf(errStr, "Invalid value found %s for the "
                                "'max-value' of FLOW-CONTROL-TX-RATE. "
                                "Continue with default value: %d. \n",
                                token, MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MAX);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->flowControlTxRateMax =
                                        MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MAX;
                }
            }
            if (mdpCommonData->flowControlTxRateMax <
                                         mdpCommonData->flowControlTxRateMin)
            {
                sprintf(errStr, "The 'min-value' should not be greater than "
                            "the 'max-value'. Continue with default values: "
                            "%d %d. \n",
                            MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MIN,
                            MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MAX);
                ERROR_ReportWarning(errStr);
            }
        }// else if (strcmp(token,"FLOW-CONTROL-TX-RATE")== 0)
        else if (strcmp(token,"TX-CACHE")== 0)
        {
            //for minCount
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                sprintf(errStr, "No value defined for TX-CACHE 'min-count' "
                               "Continue with the default value: %d. \n",
                               MDP_DEFAULT_TX_CACHE_COUNT_MIN);
                ERROR_ReportWarning(errStr);

                mdpCommonData->txCacheCountMin =
                                              MDP_DEFAULT_TX_CACHE_COUNT_MIN;
            }
            else if (!(IO_IsStringNonNegativeInteger(token)))
            {
                sprintf(errStr, "Invalid value %s for TX-CACHE 'min-count' "
                               "Continue with the default value: %d. \n",
                               token, MDP_DEFAULT_TX_CACHE_COUNT_MIN);
                ERROR_ReportWarning(errStr);

                mdpCommonData->txCacheCountMin =
                                              MDP_DEFAULT_TX_CACHE_COUNT_MIN;
            }
            else
            {
                mdpCommonData->txCacheCountMin = atoi(token);
            }

            if (token)
            {
            // for maxCount
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

                if (!token)
            {
                    sprintf(errStr, "No value defined for TX-CACHE "
                               "'max-count' Continue with the default value:"
                               " %d. \n", MDP_DEFAULT_TX_CACHE_COUNT_MAX);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->txCacheCountMax =
                                              MDP_DEFAULT_TX_CACHE_COUNT_MAX;
                }
                else if (!(IO_IsStringNonNegativeInteger(token)))
                {
                   sprintf(errStr,"Invalid value %s for TX-CACHE 'max-count'"
                                  " Continue with the default value: %d. \n",
                                   token, MDP_DEFAULT_TX_CACHE_COUNT_MAX);
                ERROR_ReportWarning(errStr);

                mdpCommonData->txCacheCountMax =
                                              MDP_DEFAULT_TX_CACHE_COUNT_MAX;
            }
            else
            {
                mdpCommonData->txCacheCountMax = atoi(token);
            }
            }
            else
            {
                sprintf(errStr, "No value defined for TX-CACHE 'max-count' "
                                "Continue with the default value: %d. \n",
                                MDP_DEFAULT_TX_CACHE_COUNT_MAX);
                ERROR_ReportWarning(errStr);

                mdpCommonData->txCacheCountMax =
                                          MDP_DEFAULT_TX_CACHE_COUNT_MAX;
            }

            if (token)
            {
            // for maxSize
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

                if (!token)
            {
                    sprintf(errStr, "No value defined for TX-CACHE "
                                "'max-size' Continue with the default value:"
                                " %d. \n", MDP_DEFAULT_TX_CACHE_SIZE_MAX);
                ERROR_ReportWarning(errStr);

                    mdpCommonData->txCacheSizeMax =
                                               MDP_DEFAULT_TX_CACHE_SIZE_MAX;
                }
                else if (!(IO_IsStringNonNegativeInteger(token)))
                {
                    sprintf(errStr,"Invalid value %s for TX-CACHE 'max-size'"
                                  " Continue with the default value: %d. \n",
                                  token, MDP_DEFAULT_TX_CACHE_SIZE_MAX);
                    ERROR_ReportWarning(errStr);

                   mdpCommonData->txCacheSizeMax =
                                               MDP_DEFAULT_TX_CACHE_SIZE_MAX;
            }
            else
            {
                mdpCommonData->txCacheSizeMax = atoi(token);
            }
            }
            else
            {
                sprintf(errStr, "No value defined for TX-CACHE 'max-size' "
                                "Continue with the default value: %d. \n",
                                MDP_DEFAULT_TX_CACHE_SIZE_MAX);
                ERROR_ReportWarning(errStr);

                mdpCommonData->txCacheSizeMax =
                                               MDP_DEFAULT_TX_CACHE_SIZE_MAX;
            }

            if (mdpCommonData->txCacheCountMax <
                                              mdpCommonData->txCacheCountMin)
            {
                sprintf(errStr, "The 'min-count' should not be greater than "
                            "the 'max-count'. Continue with default values: "
                            "%d %d. \n",
                            MDP_DEFAULT_TX_CACHE_COUNT_MIN,
                            MDP_DEFAULT_TX_CACHE_COUNT_MAX);
                ERROR_ReportWarning(errStr);
            }
        }// else if (strcmp(token,"TX-CACHE")== 0)
        else if (strcmp(token,"TX-BUFFER-SIZE")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->txBufferSize = MDP_DEFAULT_BUFFER_SIZE;
            }
            else
            {
                if (!IO_IsStringNonNegativeInteger(token))
                {
                    sprintf(errStr, "Invalid value %s for TX-BUFFER-SIZE. "
                                 "Continue with the default value: %u. \n",
                                 token, MDP_DEFAULT_BUFFER_SIZE);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->txBufferSize = MDP_DEFAULT_BUFFER_SIZE;
                }
                else
                {
                    sscanf(token, "%u", &mdpCommonData->txBufferSize);
                }
            }
        }// else if (strcmp(token,"TX-BUFFER-SIZE")== 0)
        else if (strcmp(token,"RX-BUFFER-SIZE")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->rxBufferSize = MDP_DEFAULT_BUFFER_SIZE;
            }
            else
            {
                if (!IO_IsStringNonNegativeInteger(token))
                {
                    sprintf(errStr, "Invalid value %s for RX-BUFFER-SIZE. "
                                 "Continue with the default value: %u. \n",
                                 token, MDP_DEFAULT_BUFFER_SIZE);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->rxBufferSize = MDP_DEFAULT_BUFFER_SIZE;
                }
                else
                {
                    sscanf(token, "%u", &mdpCommonData->rxBufferSize);
                }
            }
        }// else if (strcmp(token,"RX-BUFFER-SIZE")== 0)
        else if (strcmp(token,"SEGMENT-POOL-SIZE")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->segmentPoolDepth =
                                              MDP_DEFAULT_SEGMENT_POOL_DEPTH;
            }
            else
            {
                if (!IO_IsStringNonNegativeInteger(token))
                {
                    sprintf(errStr,"Invalid value %s for SEGMENT-POOL-SIZE. "
                                 "Continue with the default value: %u. \n",
                                 token, MDP_DEFAULT_SEGMENT_POOL_DEPTH);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->segmentPoolDepth =
                                              MDP_DEFAULT_SEGMENT_POOL_DEPTH;
                }
                else
                {
                    sscanf(token, "%u", &mdpCommonData->segmentPoolDepth);
                }
            }
        }// else if (strcmp(token,"SEGMENT-POOL-SIZE")== 0)
        else if (strcmp(token,"ROBUSTNESS-COUNT")== 0)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (!token)
            {
                mdpCommonData->robustFactor = MDP_DEFAULT_ROBUSTNESS;
            }
            else
            {
                if (!IO_IsStringNonNegativeInteger(token))
                {
                    sprintf(errStr,"Invalid value %s for ROBUSTNESS-COUNT. "
                                 "Continue with the default value: %u. \n",
                                 token, MDP_DEFAULT_ROBUSTNESS);
                    ERROR_ReportWarning(errStr);

                    mdpCommonData->robustFactor = MDP_DEFAULT_ROBUSTNESS;
                }
                else
                {
                    sscanf(token, "%u", &mdpCommonData->robustFactor);
                }
            }
        }// else if (strcmp(token,"ROBUSTNESS-COUNT")== 0)
        if (token)
        {
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);
        }
    }// end of while (token != NULL)
}



/*
 * NAME:        MdpFindSessionInList.
 * PURPOSE:     Find session with respect to unique tuple entry
 * PARAMETERS:  node - pointer to the node which received the message.
 *              sourceAddr - sender address
 *              remoteAddr - dest address
 *              uniqueId - unique id assigned
 * RETURN:      pointer to found MdpSession in the list else NULL.
 */
MdpSession* MdpFindSessionInList(Node* node,
                                 Address sourceAddr,
                                 Address remoteAddr,
                                 Int32 uniqueId)
{
    MdpData* mdpData = (MdpData* ) node->appData.mdp;
    std::multimap<Int32, MdpUniqueTuple*,ltcompare_mdpMap1>::const_iterator
                                                                    iterator;
    MdpUniqueTuple* uniqueTuple = NULL;

    iterator = mdpData->multimap_MdpSessionList->find(uniqueId);

    if (iterator == mdpData->multimap_MdpSessionList->end())
    {
        return NULL;
    }
    else
    {
        // having atleast one element in the list wrt uniqueId
        BOOL wasFound = FALSE;
        std::multimap<Int32, MdpUniqueTuple*, ltcompare_mdpMap1>::
                                        const_iterator iteratorUpperBound;
        iteratorUpperBound = mdpData->multimap_MdpSessionList->
                                                       upper_bound(uniqueId);

        do{
            uniqueTuple = iterator->second;

            if (!uniqueTuple)
            {
                char errStr[MAX_STRING_LENGTH];

                sprintf(errStr,"MDP: MdpUniqueTuple pointer not found for "
                               "an existing entry in map for uniqueId/port "
                               "%d at node %d\n",
                               uniqueId, node->nodeId);
                ERROR_ReportError(errStr);
                return NULL;
            }

            if (Address_IsSameAddress(&uniqueTuple->sourceAddr,&sourceAddr)
                && Address_IsSameAddress(&uniqueTuple->destAddr,&remoteAddr))
            {
                // session found
                if (!uniqueTuple->session)
                {
                    char addrStr1[MAX_STRING_LENGTH];
                    char addrStr2[MAX_STRING_LENGTH];
                    char errStr[MAX_STRING_LENGTH];

                    IO_ConvertIpAddressToString(&sourceAddr,addrStr1);
                    IO_ConvertIpAddressToString(&remoteAddr,addrStr2);

                    sprintf(errStr, "MDP: Session pointer not found for an "
                                    "existing tuple %s %s %d. at node %d\n",
                                    addrStr1, addrStr2, uniqueId,
                                    node->nodeId);
                    ERROR_ReportError(errStr);
                }

                wasFound = TRUE;
                break;
            }
            iterator++;
        }while (iterator != iteratorUpperBound);

        if (wasFound)
        {
            return uniqueTuple->session;
        }
    }

    return NULL;
}


/*
 * NAME:        MdpFindSessionInListForEXataMulticastPort.
 * PURPOSE:     Find session with respect to multicast address on exata port
 * PARAMETERS:  node - pointer to the node which received the message.
 *              multicastAddr - dest address
 *              exataPort - exata port
 * RETURN:      pointer to found MdpSession in the list else NULL.
 */
MdpSession* MdpFindSessionInListForEXataMulticastPort(Node* node,
                                                      Address multicastAddr,
                                                      Int32 exataPort)
{
    MdpData* mdpData = (MdpData* ) node->appData.mdp;
    std::multimap<Int32, MdpUniqueTuple*,ltcompare_mdpMap1>::const_iterator
                                                                    iterator;
    MdpUniqueTuple* uniqueTuple = NULL;

    iterator = mdpData->multimap_MdpSessionList->find(exataPort);

    if (iterator == mdpData->multimap_MdpSessionList->end())
    {
        return NULL;
    }
    else
    {
        // having atleast one element in the list wrt exataPort
        BOOL wasFound = FALSE;
        std::multimap<Int32, MdpUniqueTuple*, ltcompare_mdpMap1>::
                                        const_iterator iteratorUpperBound;
        iteratorUpperBound = mdpData->multimap_MdpSessionList->
                                                      upper_bound(exataPort);

        do{
            uniqueTuple = iterator->second;

            if (!uniqueTuple)
            {
                char errStr[MAX_STRING_LENGTH];

                sprintf(errStr,"MDP: MdpUniqueTuple pointer not found for "
                               "an existing entry in map for exata port "
                               "%d at node %d\n",
                               exataPort, node->nodeId);
                ERROR_ReportError(errStr);
                return NULL;
            }

            // checking for remote address only for being multicast
            if (Address_IsSameAddress(&uniqueTuple->destAddr,&multicastAddr))
            {
                // session found
                if (!uniqueTuple->session)
                {
                    char addrStr1[MAX_STRING_LENGTH];
                    char errStr[MAX_STRING_LENGTH];

                    IO_ConvertIpAddressToString(&multicastAddr,addrStr1);

                    sprintf(errStr, "MDP: Session pointer not found for an "
                                    "multicast address %s and EXata port %d "
                                    "at node %d\n",
                                    addrStr1, exataPort, node->nodeId);
                    ERROR_ReportError(errStr);
                }

                wasFound = TRUE;
                break;
            }
            iterator++;
        }while (iterator != iteratorUpperBound);

        if (wasFound)
        {
            return uniqueTuple->session;
        }
    }

    return NULL;
}


/*
 * NAME:        MdpFindSessionInPortMapList.
 * PURPOSE:     Find first session entry with respect to local address
 *              and sourcePort of the application
 * PARAMETERS:  node - pointer to the node which received the message.
 *              localAddr - node local address
 *              sourcePort - source port of the application
 * RETURN:      pointer to found MdpSession in the list else NULL.
 */
MdpSession* MdpFindSessionInPortMapList(Node* node,
                                 Address localAddr,
                                 UInt16 sourcePort)
{
    MdpData* mdpData = (MdpData* ) node->appData.mdp;
    std::multimap<UInt16, MdpSession*,ltcompare_mdpMap2>::const_iterator
                                                                    iterator;
    MdpSession* theSession = NULL;

    if (!mdpData->multimap_MdpSessionListByPort)
    {
        return NULL;
    }

    iterator = mdpData->multimap_MdpSessionListByPort->find(sourcePort);

    if (iterator == mdpData->multimap_MdpSessionListByPort->end())
    {
        return NULL;
    }
    else
    {
        theSession = iterator->second;
        if (!theSession)
        {
            char errStr[MAX_STRING_LENGTH];

            sprintf(errStr,"MDP: Session pointer not found for "
                           "sourcePort %d in portmap at node %d. "
                           "Need to check the problem. \n",
                           sourcePort, node->nodeId);
            ERROR_ReportError(errStr);

            return NULL;
        }

        return theSession;
    }
}


/*
 * NAME:        MdpAddSessionInList.
 * PURPOSE:     Add unique tuple entry with respect to new session
 * PARAMETERS:  node - pointer to the node which received the message.
 *              sourceAddr - sender address
 *              remoteAddr - dest address
 *              uniqueId - unique id assigned
 *              newSession - new session
 * RETURN:      none.
 */
void MdpAddSessionInList(Node* node,
                         Address sourceAddr,
                         Address remoteAddr,
                         Int32 uniqueId,
                         MdpSession* newSession)
{
    MdpData* mdpData = (MdpData* ) node->appData.mdp;
    MdpUniqueTuple* uniqueTuple = NULL;

    if (!mdpData)
    {
        char errStr[MAX_STRING_LENGTH];

        sprintf(errStr, "MDP not found for node %d\n",
                        node->nodeId);
        ERROR_ReportError(errStr);
    }

    std::multimap<Int32, MdpUniqueTuple*, ltcompare_mdpMap1>::const_iterator
                                                                    iterator;

    iterator = mdpData->multimap_MdpSessionList->find(uniqueId);

    if (iterator == mdpData->multimap_MdpSessionList->end())
    {
        // create new
        uniqueTuple = (MdpUniqueTuple*) MEM_malloc(sizeof(MdpUniqueTuple));
        memcpy(&uniqueTuple->sourceAddr,
               &sourceAddr, sizeof(Address));
        memcpy(&uniqueTuple->destAddr,
               &remoteAddr, sizeof(Address));
        uniqueTuple->session = newSession;

        mdpData->multimap_MdpSessionList->insert(pair<Int32, MdpUniqueTuple*>
                                                    (uniqueId, uniqueTuple));
    }
    else
    {
        // already having atleast one element in the list wrt uniqueId
        BOOL wasFound = FALSE;
        std::multimap<Int32, MdpUniqueTuple*, ltcompare_mdpMap1>::
                                        const_iterator iteratorUpperBound;

        iteratorUpperBound = mdpData->multimap_MdpSessionList->
                                                       upper_bound(uniqueId);

        do{
            uniqueTuple = iterator->second;

            if (Address_IsSameAddress(&uniqueTuple->sourceAddr, &sourceAddr)
                && Address_IsSameAddress(&uniqueTuple->destAddr, &remoteAddr)
                && uniqueTuple->session == newSession)
            {
                wasFound = TRUE;
                break;
            }
            iterator++;
        }while (iterator != iteratorUpperBound);

        if (!wasFound)
        {
            // create new
            uniqueTuple =(MdpUniqueTuple*)MEM_malloc(sizeof(MdpUniqueTuple));
            memcpy(&uniqueTuple->sourceAddr,
                   &sourceAddr, sizeof(Address));
            memcpy(&uniqueTuple->destAddr,
                   &remoteAddr, sizeof(Address));
            uniqueTuple->session = newSession;

            mdpData->multimap_MdpSessionList->insert
                       (pair<Int32, MdpUniqueTuple*>(uniqueId, uniqueTuple));
        }
    }
}


/*
 * NAME:        MdpAddSessionInPortMapList.
 * PURPOSE:     Add session entry with respect to port number in portMap, if
 *              not exist
 * PARAMETERS:  node - pointer to the node which received the message.
 *              sourcePort - sourcePort of the application
 *              newSession - new session
 * RETURN:      void.
 */
void MdpAddSessionInPortMapList(Node* node,
                         UInt16 sourcePort,
                         MdpSession* newSession)
{
    MdpData* mdpData = (MdpData* ) node->appData.mdp;

    if (!mdpData)
    {
        char errStr[MAX_STRING_LENGTH];

        sprintf(errStr, "MDP not found for node %d\n",
                        node->nodeId);
        ERROR_ReportError(errStr);
    }

    if (!mdpData->multimap_MdpSessionListByPort)
    {
        mdpData->multimap_MdpSessionListByPort =
                new std::multimap<UInt16, MdpSession*, ltcompare_mdpMap2>;
    }

    std::multimap<UInt16, MdpSession*, ltcompare_mdpMap2>::const_iterator
                                                                    iterator;

    iterator = mdpData->multimap_MdpSessionListByPort->find(sourcePort);

    if (iterator == mdpData->multimap_MdpSessionListByPort->end())
    {
        // create new
        mdpData->multimap_MdpSessionListByPort->insert(
                    pair<UInt16, MdpSession*> (sourcePort, newSession));
    }
    else
    {
        // already having entry in the list wrt sourcePort
        return;
    }
    return;
}

/*
 * NAME:        MdpPersistentInfoForSessionInList.
 * PURPOSE:     Filling persistent info w.r.t existing session in list
 * PARAMETERS:  node - pointer to the node which received the message.
 *              mdpInfo - pointer to MdpPersistentInfo
 *              session - existing session
 * RETURN:      none.
 */
void MdpPersistentInfoForSessionInList(Node* node,
                                       MdpPersistentInfo* mdpInfo,
                                       MdpSession* session)
{
    MdpData* mdpData = (MdpData* ) node->appData.mdp;
    Int32 uniqueId = session->GetUniqueId();
    MdpUniqueTuple* uniqueTuple = NULL;
    std::multimap<Int32, MdpUniqueTuple*,ltcompare_mdpMap1>::const_iterator
                                                                    iterator;

    iterator = mdpData->multimap_MdpSessionList->find(uniqueId);

    if (iterator == mdpData->multimap_MdpSessionList->end())
    {
        char errStr[MAX_STRING_LENGTH];

        sprintf(errStr, "MDP: MdpUniqueTuple pointer not found for "
                        "uniqueId %d in map in function "
                        "MdpPersistentInfoForSessionInList at node %d\n",
                        uniqueId, node->nodeId);
        ERROR_ReportError(errStr);
    }

    // having atleast one element in the list wrt uniqueId
    BOOL wasFound = FALSE;
    std::multimap<Int32, MdpUniqueTuple*, ltcompare_mdpMap1>::const_iterator
                                                          iteratorUpperBound;
    iteratorUpperBound = mdpData->multimap_MdpSessionList->
                                                       upper_bound(uniqueId);

    do{
        uniqueTuple = iterator->second;

        if (!uniqueTuple)
        {
            char errStr[MAX_STRING_LENGTH];

            sprintf(errStr, "MDP: MdpUniqueTuple pointer not found for an "
                            "existing entry in map for finding session "
                            "in function MdpPersistentInfoForSessionInList "
                            "at node %d\n",
                            node->nodeId);
            ERROR_ReportError(errStr);
        }

        if (uniqueTuple->session == session)
        {
            // session found
            memcpy(&mdpInfo->clientAddr,
                   &uniqueTuple->sourceAddr,
                   sizeof(Address));
            memcpy(&mdpInfo->remoteAddr,
                   &uniqueTuple->destAddr,
                   sizeof(Address));
            mdpInfo->uniqueId = uniqueId;
            wasFound = TRUE;
            break;
        }
        iterator++;
    }while (iterator != iteratorUpperBound);

    if (!wasFound)
    {
        char errStr[MAX_STRING_LENGTH];

        sprintf(errStr, "MDP: Session not found in any of the existing map "
                        "entry for uniqueId %d in function "
                        "MdpPersistentInfoForSessionInList at node %d\n",
                        uniqueId, node->nodeId);
        ERROR_ReportError(errStr);
    }
}


//--------------------------------------------------------------------------
// NAME         : MdpInit()
// PURPOSE      : Initializes MDP model.
// PARAMETERS       :
//          node    : A pointer to Node
//        nodeInput : A pointer to NodeInput
//
// RETURN VALUE : None.
//--------------------------------------------------------------------------
void MdpInit(Node* node, const NodeInput* nodeInput)
{
    BOOL wasFound = FALSE;
    BOOL found = FALSE;
    BOOL retValue = FALSE;
    BOOL profileFound = FALSE;
    NodeInput profileInput;
    NodeInput appInput;
    Int32 i = 0;
    Int32 j = 0;
    char* token = NULL;
    char* next = NULL;
    char delims[] = {" \t"};
    char iotoken[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    char globalProfile[MAX_STRING_LENGTH];
    char errStr[MAX_STRING_LENGTH];
    char tempStr[MAX_STRING_LENGTH];

    MdpData* mdpData = (MdpData*) node->appData.mdp;

    if (mdpData == NULL)
    {
        // Allocate Mdp struct
        mdpData = (MdpData* ) MEM_malloc(sizeof(MdpData));
        memset(mdpData, 0, sizeof(MdpData));
        node->appData.mdp = (void *) mdpData;

        mdpData->sessionManager = NULL;
        mdpData->mdpSessionHandle = NULL;
        mdpData->totalSession = 0;

        RANDOM_SetSeed(mdpData->seed,
                       node->globalSeed,
                       node->nodeId,
                       APP_MDP);

        mdpData->sourcePort = 0;

        // init mdpData->mdpCommonData
        mdpData->mdpCommonData = new MdpCommonParameters();

        MdpInitOptParamWithDefaultValues(node,
                                         mdpData->mdpCommonData,
                                         nodeInput);

        mdpData->multimap_MdpSessionList =
                new std::multimap<Int32, MdpUniqueTuple*, ltcompare_mdpMap1>;

        // delaying memory allocation for map multimap_MdpSessionListByPort
        // until it is really required. Memory allocation is done in function
        // MdpAddSessionInPortMapList()

        // delaying memory allocation for vector outPortList
        // until it is really required. Memory allocation is done in function
        // MdpAddPortInExataOutPortList()

        mdpData->receivePortList = new std::vector <UInt16>(0);

        // populate MdpFileCache pointer
        mdpData->temp_file_cache = new MdpFileCache;
        mdpData->temp_file_cache->SetCacheSize(
                                      MDP_DEFAULT_FILE_CACHE_COUNT_MIN,
                                      MDP_DEFAULT_FILE_CACHE_COUNT_MAX,
                                      MDP_DEFAULT_FILE_CACHE_SIZE_MAX);

        // searching for global profile defined on Node level for this node.

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "MDP-PROFILE",
            &retValue,
            buf);

        if (retValue)
        {
            sprintf(globalProfile, "%s" , buf);
            profileFound = TRUE;
        }

        if (profileFound)
        {
            IO_ReadCachedFile(node->nodeId,
                              ANY_ADDRESS,
                              nodeInput,
                              "MDP-PROFILE-FILE",
                              &wasFound,
                              &profileInput);

            if (wasFound == FALSE)
            {
                sprintf(errStr,"MDP: Needs MDP-PROFILE-FILE "
                               "for profile name %s.\n",globalProfile);

                ERROR_ReportError(errStr);
            }

            for (i = 0; i < profileInput.numLines; i++)
            {
                token = IO_GetDelimitedToken(iotoken,
                                             profileInput.inputStrings[i],
                                             delims,
                                             &next);

                if (!token ||(strcmp(token,"MDP-PROFILE")!= 0))
                {
                    continue;
                }

                token = IO_GetDelimitedToken(iotoken, next, delims, &next);

                if (token && strcmp(token,globalProfile) == 0)
                {
                    found = TRUE;
                    for (j = i + 1; j < profileInput.numLines; j++)
                    {
                        sscanf(profileInput.inputStrings[j],"%s",tempStr);
                        if (strcmp(tempStr,"MDP-PROFILE") == 0)
                        {
                            break;
                        }
                        MdpInitializeOptionalParameters(node,
                                                profileInput.inputStrings[j],
                                                mdpData->mdpCommonData);
                    }
                }
                else
                {
                    continue;
                }

                if (found == TRUE)
                {
                    break;
                }
            }// for (i = 0; i < profileInput.numLines; i++)
        }

        wasFound = FALSE;

        IO_ReadCachedFile(node->nodeId,
                          ANY_ADDRESS,
                          nodeInput,
                          "APP-CONFIG-FILE",
                          &wasFound,
                          &appInput);

        if (wasFound == FALSE)
        {
            mdpData->maxAppLines = 0;
        }
        else
        {
            mdpData->maxAppLines = appInput.numLines;
        }

        wasFound = FALSE;

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "MDP-STATISTICS",
            &wasFound,
            buf);

        if (wasFound && !(strcmp(buf,"YES")))
        {
            mdpData->mdpStats = TRUE;
        }
        else
        {
            mdpData->mdpStats = FALSE;
        }

        wasFound = FALSE;

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "MDP-EXATA-INCOMING-PORTS",
            &wasFound,
            buf);

        if (wasFound)
        {
            token = IO_GetDelimitedToken(iotoken, buf, delims, &next);

            if (!token)
            {
                sprintf(errStr, "No value found for the "
                           "MDP-EXATA-INCOMING-PORTS list. "
                           "Continue without any value. \n");

                ERROR_ReportWarning(errStr);
            }

            BOOL isPortFound = FALSE;
            UInt16 port = 0;

            while (token)
            {
                if (!IO_IsStringNonNegativeInteger(token))
                {
                    sprintf(errStr, "Invalid value found %s in the "
                               "MDP-EXATA-INCOMING-PORTS list. "
                               "Continue by ignoring this value. \n",
                               token);
                    ERROR_ReportWarning(errStr);

                    token = IO_GetDelimitedToken(iotoken,next,delims,&next);
                    continue;
                }

                isPortFound = FALSE;
                port = (UInt16)atoi(token);

                for (Int32 i = 0;i < (Int32)mdpData->receivePortList->size();i++)
                {
                    if ((*mdpData->receivePortList)[i] == port)
                    {
                        isPortFound = TRUE;
                        break;
                    }
                }

                if (!isPortFound)
                {
                    mdpData->receivePortList->push_back(port);
                }

                token = IO_GetDelimitedToken(iotoken, next, delims, &next);
            }
        }
    }
}


//--------------------------------------------------------------------------
// NAME         : MdpNewSessionInit()
// PURPOSE      : Initializes MDP session for the application.
// PARAMETERS       :
//          node    : A pointer to Node
//        localAddr : Local address
//       remoteAddr : Destination address
//         uniqueId : Unique id for session
//       sourcePort : Source port for application
//          appType : AppType of application
//    mdpCommonData : Pointer to struct MdpCommonParameters
//
// RETURN VALUE : MdpSession.
//--------------------------------------------------------------------------
MdpSession* MdpNewSessionInit(Node* node,
                      Address localAddr,
                      Address remoteAddr,
                      Int32 uniqueId,
                      Int32 sourcePort,
                      AppType appType,
                      MdpCommonParameters* mdpCommonData)
{
    MdpSession* theSession = NULL;
    Int32 i;

    MdpData* mdpData = (MdpData*) node->appData.mdp;

    if (!mdpData->sessionManager)
    {
        MdpProtoTimerMgr* timerMgr = new MdpProtoTimerMgr();

        // local node id for session manager should be default IPv4
        // interface address.In case when there is no IPv4 inteface
        // then node->nodeId will be considered as local node id
        NodeAddress localNodeId = GetDefaultIPv4InterfaceAddress(node);

        if (localNodeId == ANY_ADDRESS)
        {
            localNodeId = node->nodeId;
        }
        mdpData->sessionManager = new MdpSessionMgr(*timerMgr, localNodeId);
    }

    // initiating new session
    theSession = mdpData->sessionManager->NewSession(node);

    // increasing session count by one
    mdpData->totalSession++;

    theSession->SetLocalAddr(MdpGetProtoAddress(localAddr,
                                            (UInt16)sourcePort));
    theSession->SetAddr(MdpGetProtoAddress(remoteAddr,
                                        (UInt16)sourcePort));

    theSession->SetUniqueId(uniqueId);
    theSession->SetAppType(appType);
    theSession->SetTOS((unsigned char)mdpCommonData->tos);
    theSession->SetTxRate(mdpCommonData->txRate);
    theSession->SetTTL((unsigned char)mdpCommonData->ttlCount);
    theSession->SetGrttEstimate(mdpCommonData->initialGrtt);
    theSession->SetSegmentSize(mdpCommonData->segmentSize);
    theSession->SetBlockSize(mdpCommonData->blockSize);
    theSession->SetNumParity(mdpCommonData->numParity);
    theSession->SetNumAutoParity(mdpCommonData->numAutoParity);
    theSession->SetStatusReporting(mdpCommonData->reportMsgEnabled);
    theSession->SetUnicastNacks(mdpCommonData->unicastNackEnabled);
    theSession->SetMulticastAcks(mdpCommonData->multicastAckEnabled);
    theSession->SetClientAcking(mdpCommonData->positiveAckEnabled);
    theSession->SetEmconServer(mdpCommonData->emconEnabled);
    theSession->SetEmconClient(mdpCommonData->emconEnabled);
    theSession->SetMulticastLoopback(mdpCommonData->loopbackEnabled);

    for (i = 0; i < (Int32)mdpCommonData->ackList->size(); i++)
    {
       theSession->AddAckingNode((*mdpCommonData->ackList)[i]);
    }

    theSession->SetBaseObjectTransportId(mdpCommonData->baseObjectId);
    theSession->SetArchiveMode(mdpCommonData->archiveModeEnabled);
    theSession->SetArchiveDirectory(mdpCommonData->archivePath);
    theSession->SetStreamIntegrity(mdpCommonData->streamIntegrityEnabled);
    theSession->SetCongestionControl(mdpCommonData->flowControlEnabled);
    theSession->SetTxRateBounds(mdpCommonData->flowControlTxRateMin,
                                mdpCommonData->flowControlTxRateMax);
    theSession->SetTxCacheDepth((UInt32)mdpCommonData->txCacheCountMin,
                                (UInt32)mdpCommonData->txCacheCountMax,
                                (UInt32)mdpCommonData->txCacheSizeMax);

    theSession->SetSessionTxBufferSize((UInt32)mdpCommonData->txBufferSize);
    theSession->SetSessionRxBufferSize((UInt32)mdpCommonData->rxBufferSize);
    theSession->SetSegmentPoolDepth(mdpCommonData->segmentPoolDepth);
    theSession->SetRobustFactor((UInt32)mdpCommonData->robustFactor);

    return theSession;
}



//--------------------------------------------------------------------------
// NAME         : MdpCreateOpenNewMdpSessionForNode()
// PURPOSE      : Create & Open new MDP session for the new app MDP server
//                packets received from both simulation and emulation nodes.
// PARAMETERS       :
//          node    : A pointer to Node
//          msg     : Pointer to Message
// RETURN VALUE : MdpSession.
//--------------------------------------------------------------------------
MdpSession* MdpCreateOpenNewMdpSessionForNode(Node* node,
                                              Message* msg)
{
    BOOL found = FALSE;
    BOOL isMulticast = FALSE;
    BOOL isEXataPort = FALSE;
    MdpSession* session = NULL;
    UdpToAppRecv* info = NULL;
    MdpPersistentInfo* mdpInfo = NULL;
    MdpCommonParameters mdpCommonData;

    MdpData* mdpData = (MdpData*) node->appData.mdp;
    MdpCommonParameters* passCommonData = mdpData->mdpCommonData;

    info = (UdpToAppRecv*) MESSAGE_ReturnInfo(msg);
    mdpInfo = (MdpPersistentInfo*) MESSAGE_ReturnInfo(msg,
                                              INFO_TYPE_MdpInfoData);

    isEXataPort = MdpIsExataIncomingPort(node, info->destPort);
    isMulticast = MdpIsMulticastAddress(node, &info->destAddr);

    if (!isEXataPort)
    {
        found = MdpReadProfileFromApp(node,
                                  mdpInfo->uniqueId,
                                  &mdpCommonData);
    }
    if (found)
    {
        // giving preference to profile defined in .app
        passCommonData = &mdpCommonData;
    }

    Address localAddr = MAPPING_GetDefaultInterfaceAddressInfoFromNodeId(
                                  node,
                                  node->nodeId,
                                  info->destAddr.networkType);


    if (!mdpInfo && !isEXataPort)
    {
        // print error message as this case should not
        // happen in simulation mode
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "Please check whether the port %d "
                        "is MDP's external application "
                        "communication port. If yes then "
                        "add it in the MDP port number list "
                        "configured on node %d using configuration "
                        "parameter MDP-EXATA-INCOMING-PORTS. \n",
                        info->destPort, node->nodeId);
        ERROR_ReportError(errStr);
    }

    if (!mdpInfo)
    {
        // now dealing with MDP packets received from the
        // EXata external mapped nodes 
        if (isMulticast)
        {
            if (MdpIsServerPacket(node, msg))
            {
                session = MdpNewSessionInit(node,
                                   localAddr,
                                   info->destAddr,
                                   info->destPort,                // for mdpInfo->uniqueId
                                   info->sourcePort,
                                   MdpGetAppTypeForServer(
                                        (AppType)info->destPort), // for mdpInfo->appType
                                   passCommonData);
            }
            else
            {
                session = MdpNewSessionInit(node,
                               localAddr,
                               info->destAddr,
                               info->destPort,                    // for mdpInfo->uniqueId
                               info->sourcePort,
                               (AppType)info->destPort,           // for mdpInfo->appType
                               passCommonData);
            }

            // resetting destination port
            session->SetAddr(MdpGetProtoAddress(info->destAddr,
                               (UInt16)info->destPort));          // for mdpInfo->destPort
        }
        else
        {
            session = MdpNewSessionInit(node,
                               localAddr,
                               info->sourceAddr,                  // for mdpInfo->clientAddr
                               info->destPort,                    // for mdpInfo->uniqueId
                               info->destPort,                    // for mdpInfo->destPort  // i.e. source port
                               MdpGetAppTypeForServer(
                                        (AppType)info->destPort), // for mdpInfo->appType
                               passCommonData);
        }

        // now adding unique entry for session in the MdpUniqueTupleList
        if (isMulticast)
        {
            MdpAddSessionInList(node,
                                localAddr,         // for mdpInfo->clientAddr
                                info->destAddr,    // for mdpInfo->remoteAddr
                                info->destPort,    // for mdpInfo->uniqueId
                                session);
        }
        else
        {
            MdpAddSessionInList(node,
                                info->sourceAddr,  // for mdpInfo->clientAddr
                                info->destAddr,    // for mdpInfo->remoteAddr
                                info->destPort,    // for mdpInfo->uniqueId
                                session);
        }
    }
    else // else of if (!mdpInfo) for simulation nodes MDP packet
    {
        if (isMulticast)
        {
            if (MdpIsServerPacket(node, msg))
            {
                session = MdpNewSessionInit(node,
                                   localAddr,
                                   info->destAddr,
                                   mdpInfo->uniqueId,
                                   info->sourcePort,
                                   MdpGetAppTypeForServer(mdpInfo->appType),
                                   passCommonData);
            }
            else
            {
                session = MdpNewSessionInit(node,
                               localAddr,
                               info->destAddr,
                               mdpInfo->uniqueId,
                               info->sourcePort,
                               mdpInfo->appType,
                               passCommonData);
            }

            // resetting destination port
            session->SetAddr(MdpGetProtoAddress(info->destAddr,
                               (UInt16)mdpInfo->destPort));
        }
        else
        {
            session = MdpNewSessionInit(node,
                               localAddr,
                               mdpInfo->clientAddr,
                               mdpInfo->uniqueId,
                               mdpInfo->destPort,  //source port
                               MdpGetAppTypeForServer(mdpInfo->appType),
                               passCommonData);

            // resetting destination port
            if (!isEXataPort)
            {
                session->SetAddr(
                            MdpGetProtoAddress(mdpInfo->clientAddr,
                               (UInt16)mdpInfo->sourcePort));
            }
        }

        // now adding unique entry for session in the MdpUniqueTupleList
        MdpAddSessionInList(node,
                            mdpInfo->clientAddr,
                            mdpInfo->remoteAddr,
                            mdpInfo->uniqueId,
                            session);
    }

    // opening MDP server
    MdpError err = session->OpenClient(
                             session->GetSessionRxBufferSize());

    if (err != MDP_ERROR_NONE)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr,"Error in opening MDP receiver on "
                       "node %d. (Error = %d)\n",
                       node->nodeId, err);
        ERROR_ReportError(errStr);
    }

    return session;
}


/*
 * NAME:        MdpProcessEvent.
 * PURPOSE:     Models the behaviour of Mdp on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
MdpProcessEvent(Node* node, Message* msg)
{

    MdpData* mdpData = (MdpData*) node->appData.mdp;
    MdpSession* session = NULL;
    BOOL freeMsg = TRUE;

    if (mdpData == NULL)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "Node %d receive MDP packet but does not support "
                        "MDP \n", node->nodeId);
        ERROR_ReportError(errStr);
    }

    if (MDP_DEBUG)
    {
        char clockStr[MAX_CLOCK_STRING_LENGTH];
        ctoa(node->getNodeTime(), clockStr);
        printf("MDP: at %s: partition %d Node %3d executing "
               "event %3d on interface %2d\n",
               clockStr,
               node->partitionData->partitionId,
               node->nodeId,
               msg->eventType,
               msg->instanceId);
        fflush(stdout);
    }

    switch (msg->eventType)
    {
        case MSG_APP_FromTransport:
        {
            UdpToAppRecv* info;
            MdpPersistentInfo* mdpInfo;
            BOOL isMulticast = FALSE;
            BOOL isEXataPort = FALSE;
            char* packetData = NULL;
            MdpProtoAddress clientAddr;

            info = (UdpToAppRecv*) MESSAGE_ReturnInfo(msg);
            mdpInfo = (MdpPersistentInfo*) MESSAGE_ReturnInfo(msg,
                                                      INFO_TYPE_MdpInfoData);
            // trace recd pkt
            ActionData acnData;
            acnData.actionType = RECV;
            acnData.actionComment = NO_COMMENT;
            TRACE_PrintTrace(node,
                             msg,
                             TRACE_APPLICATION_LAYER,
                             PACKET_IN,
                             &acnData);

            isEXataPort = MdpIsExataIncomingPort(node, info->destPort);
            isMulticast = MdpIsMulticastAddress(node, &info->destAddr);

            // before searching session first check whether the packet is
            // from external EXata node, if yes then do ntoh and then find
            // session. Here !mdpInfo means packet coming from external world
            if (!mdpInfo && isEXataPort)
            {
                if (mdpData->sessionManager)
                {
                    // check whether the packet is from EXata receiver node,
                    // It happens when packet is unicast ACK, or NACK,
                    // or REPORT packet, transmitted to source port
                    // of the QualNet sender node. This handling is for the
                    // case when tx and rx MDP ports are different
                    Address localAddr =
                          MAPPING_GetDefaultInterfaceAddressInfoFromNodeId(
                                                 node,
                                                 node->nodeId,
                                                 info->destAddr.networkType);

                    if (Address_IsSameAddress(&info->destAddr, &localAddr))
                    {
                        // now find session using localAddr and
                        // info->destPort. Here info->destPort is actually
                        // the sourcePort of the MDP sender application
                        session = MdpFindSessionInPortMapList(node,
                                                     localAddr,
                                                     (UInt16)info->destPort);
                    }
                }

                // do ntoh for all MDP external incomming packets
                // as they are currently not handled from mdp_interface.cpp
                MdpSwapIncomingPacketForNtoh(node, msg);
            }

            if (!session)
            {
                if (!mdpInfo)
                {
                    // EXata: external mapped nodes 
                    // search for mdp session wrt exata port
                    if (isMulticast)
                    {
                        session = MdpGetSessionForEXataPortOnMulticast(node,
                                                        info->destAddr,
                                                        info->destPort);                    
                    }
                    else
                    {
                        session = MdpGetSessionForEXataPort(node,
                                                    info->sourceAddr,
                                                    info->destAddr,
                                                    info->destPort);

                        if (!session)
                        {
                            // trying to find out the session in other way
                            session = MdpGetSessionForEXataPort(node,
                                                        info->destAddr,
                                                        info->sourceAddr,
                                                        info->destPort);
                        }
                    }
                }
                else
                {
                    session = MdpFindSessionInList(node,
                                               mdpInfo->clientAddr,
                                               mdpInfo->remoteAddr,
                                               mdpInfo->uniqueId);
                }
            }

            if (!session && MDP_DEBUG)
            {
                printf("MDP Session not found. Going to init new session "
                       "on node %d.\n", node->nodeId);
            }

            if (!session)
            {
                session = MdpCreateOpenNewMdpSessionForNode(node, msg);
            }

            // getting MdpProtoAddress
            clientAddr = MdpGetProtoAddress(info->sourceAddr,
                                            info->sourcePort);

            packetData = MESSAGE_ReturnPacket(msg);

            Int32 virtualSize = 0;

            if (mdpInfo)
            {
                virtualSize = mdpInfo->virtualSize;
            }

            // Before going to handle the packet check whether the
            // communication port have a receiver application.
            // Checking the receiverApp status, which was assumed to be
            // TRUE first time the session was created
            if (!session->GetReceiverAppExistStatus())
            {
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr, "No application protocol found running "
                                "on MDP communication port number %d. "
                                "Hence discarding the received "
                                "packet. \n",
                                info->destPort);
                ERROR_ReportWarning(errStr);

                // Free message and simply return.
                freeMsg = TRUE;
                break;
            }

            // handle receive packet
            session->HandleRecvPacket(packetData,
                                      msg->packetSize,
                                      &clientAddr,
                                      !isMulticast,
                                      (char*)info,
                                      msg,
                                      virtualSize);

            freeMsg = FALSE;
            break;
        }
        case MSG_APP_TimerExpired:
        {
            struct_mdpTimerInfo* mdpInfo = NULL;
            mdpInfo = (struct_mdpTimerInfo*)MESSAGE_ReturnInfo(msg);

            if (MDP_DEBUG)
            {
                char clockStr[MAX_CLOCK_STRING_LENGTH];
                ctoa(node->getNodeTime(), clockStr);
                printf("MDP: at %s: on receiving event %3d Node %3d "
                       "executing MDP timer event %3d on interface %2d\n",
                       clockStr,
                       msg->eventType,
                       node->nodeId,
                       mdpInfo->mdpEventType,
                       msg->instanceId);
                fflush(stdout);
            }

            switch (mdpInfo->mdpEventType)
            {
                case GRTT_REQ_TIMEOUT:
                {
                    MdpSession* session = (MdpSession*) mdpInfo->mdpclassPtr;
                    session->OnGrttReqTimeout();
                    break;
                }
                case TX_INTERVAL_TIMEOUT:
                {
                    MdpSession* session = (MdpSession*) mdpInfo->mdpclassPtr;
                    session->OnTxIntervalTimeout();
                    break;
                }
                case TX_TIMEOUT:
                {
                    MdpSession* session = (MdpSession*) mdpInfo->mdpclassPtr;
                    session->OnTxTimeout();

                    freeMsg = FALSE;
                    break;
                }
                case REPORT_TIMEOUT:
                {
                    MdpSession* session = (MdpSession*) mdpInfo->mdpclassPtr;
                    session->OnReportTimeout();
                    break;
                }
                case ACK_TIMEOUT:
                {
                    MdpServerNode* serverNode =
                                      (MdpServerNode*) mdpInfo->mdpclassPtr;
                    serverNode->OnAckTimeout();
                    break;
                }
                case ACTIVITY_TIMEOUT:
                {
                    MdpServerNode* serverNode =
                                      (MdpServerNode*) mdpInfo->mdpclassPtr;
                    serverNode->OnActivityTimeout();

                    freeMsg = FALSE;
                    break;
                }
                case REPAIR_TIMEOUT:
                {
                    MdpServerNode* serverNode =
                                      (MdpServerNode*) mdpInfo->mdpclassPtr;
                    serverNode->OnRepairTimeout();

                    freeMsg = FALSE;
                    break;
                }
                case OBJECT_REPAIR_TIMEOUT:
                {
                    MdpObject* object = (MdpObject*) mdpInfo->mdpclassPtr;
                    object->OnRepairTimeout();
                    break;
                }
                case TX_HOLD_QUEUE_EXPIRY_TIMEOUT:
                {
                    MdpSession* session = (MdpSession*) mdpInfo->mdpclassPtr;
                    session->OnTxHoldQueueExpiryTimeout();

                    freeMsg = FALSE;
                    break;
                }
                case SESSION_CLOSE_TIMEOUT:
                {
                    MdpSession* session = (MdpSession*) mdpInfo->mdpclassPtr;
                    session->OnSessionCloseTimeout();
                    break;
                }
                default:
                {
                    // invalid message
                    char errStr[MAX_STRING_LENGTH];
                    sprintf(errStr,"Invalid message received at node %d "
                                    " for MDP event type %d\n",
                                    node->nodeId, mdpInfo->mdpEventType);
                    ERROR_ReportError(errStr);
                }
            }
            break;
        }
        default:
        {
            // invalid message
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr,"Invalid message received at node %d \n",
                            node->nodeId);
            ERROR_ReportError(errStr);
        }
    }

    if (freeMsg)
    {
        MESSAGE_Free(node, msg);
    }
}



/*
 * NAME:        MdpAddSessionStatsCount.
 * PURPOSE:     Add stats for the session
 * PARAMETERS:  session - pointer to existing session.
 *              totalCommonStats - pointer to MdpCommonStats having
 *                                 aggregate info
 *              commonStats - pointer to MdpCommonStats of session
 *              totalClientStat - pointer to MdpClientStats having
 *                                aggregate info
 *              clientStat - pointer to MdpClientStats of session
 * RETURN:      none.
 */
void MdpAddSessionStatsCount(MdpSession* session,
                             MdpCommonStats* totalCommonStats,
                             MdpCommonStats* commonStats,
                             MdpClientStats* totalClientStat,
                             MdpClientStats* clientStat)
{
    totalCommonStats->numCmdMsgSentCount += commonStats->numCmdMsgSentCount;
    totalCommonStats->numCmdMsgRecCount += commonStats->numCmdMsgRecCount;
    totalCommonStats->numCmdFlushMsgSentCount +=
                                        commonStats->numCmdFlushMsgSentCount;
    totalCommonStats->numCmdFlushMsgRecCount +=
                                         commonStats->numCmdFlushMsgRecCount;
    totalCommonStats->numCmdSquelchMsgSentCount +=
                                      commonStats->numCmdSquelchMsgSentCount;
    totalCommonStats->numCmdSquelchMsgRecCount +=
                                       commonStats->numCmdSquelchMsgRecCount;
    totalCommonStats->numCmdAckReqMsgSentCount +=
                                       commonStats->numCmdAckReqMsgSentCount;
    totalCommonStats->numCmdAckReqMsgRecCount +=
                                        commonStats->numCmdAckReqMsgRecCount;
    totalCommonStats->numPosAckMsgSentCount +=
                                          commonStats->numPosAckMsgSentCount;
    totalCommonStats->numPosAckMsgRecCount +=
                                           commonStats->numPosAckMsgRecCount;
    totalCommonStats->numCmdGrttReqMsgSentCount +=
                                      commonStats->numCmdGrttReqMsgSentCount;
    totalCommonStats->numCmdGrttReqMsgRecCount +=
                                       commonStats->numCmdGrttReqMsgRecCount;
    totalCommonStats->numGrttAckMsgSentCount +=
                                         commonStats->numGrttAckMsgSentCount;
    totalCommonStats->numGrttAckMsgRecCount +=
                                          commonStats->numGrttAckMsgRecCount;
    totalCommonStats->numCmdNackAdvMsgSentCount +=
                                      commonStats->numCmdNackAdvMsgSentCount;
    totalCommonStats->numCmdNackAdvMsgRecCount +=
                                       commonStats->numCmdNackAdvMsgRecCount;
    totalCommonStats->numNackMsgSentCount +=
                                            commonStats->numNackMsgSentCount;
    totalCommonStats->numNackMsgRecCount += commonStats->numNackMsgRecCount;
    totalCommonStats->numReportMsgSentCount +=
                                          commonStats->numReportMsgSentCount;
    totalCommonStats->numReportMsgRecCount +=
                                           commonStats->numReportMsgRecCount;
    totalCommonStats->numInfoMsgSentCount +=
                                            commonStats->numInfoMsgSentCount;
    totalCommonStats->numInfoMsgRecCount += commonStats->numInfoMsgRecCount;
    totalCommonStats->numDataMsgSentCount +=
                                            commonStats->numDataMsgSentCount;
    totalCommonStats->numDataMsgRecCount += commonStats->numDataMsgRecCount;
    totalCommonStats->numParityMsgSentCount +=
                                          commonStats->numParityMsgSentCount;
    totalCommonStats->numParityMsgRecCount +=
                                           commonStats->numParityMsgRecCount;
    totalCommonStats->numDataObjFailToQueue +=
                                          commonStats->numDataObjFailToQueue;
    totalCommonStats->numFileObjFailToQueue +=
                                          commonStats->numFileObjFailToQueue;
    totalCommonStats->senderTxRate += commonStats->senderTxRate;
    totalCommonStats->totalBytesSent += commonStats->totalBytesSent;

    if (totalClientStat && clientStat)
    {
        totalClientStat->duration += clientStat->duration;
        totalClientStat->success += clientStat->success;
        totalClientStat->active += clientStat->active;
        totalClientStat->fail += clientStat->fail;
        totalClientStat->resync += clientStat->resync;

        totalClientStat->blk_stat.count += clientStat->blk_stat.count;
        totalClientStat->blk_stat.lost_00 += clientStat->blk_stat.lost_00;
        totalClientStat->blk_stat.lost_05 += clientStat->blk_stat.lost_05;
        totalClientStat->blk_stat.lost_10 += clientStat->blk_stat.lost_10;
        totalClientStat->blk_stat.lost_20 += clientStat->blk_stat.lost_20;
        totalClientStat->blk_stat.lost_40 += clientStat->blk_stat.lost_40;
        totalClientStat->blk_stat.lost_50 += clientStat->blk_stat.lost_50;

        totalClientStat->tx_rate += clientStat->tx_rate;
        totalClientStat->nack_cnt += clientStat->nack_cnt;
        totalClientStat->supp_cnt += clientStat->supp_cnt;

        totalClientStat->buf_stat.buf_total +=
                                              clientStat->buf_stat.buf_total;
        UInt32 usuageCount = session->ClientBufferPeakValue();
        if (totalClientStat->buf_stat.peak < usuageCount)
        {
            totalClientStat->buf_stat.peak = usuageCount;
        }
        totalClientStat->buf_stat.overflow +=session->ClientBufferOverruns();

        totalClientStat->goodput += clientStat->goodput;
        totalClientStat->rx_rate += clientStat->rx_rate;
        totalClientStat->bytes_recv += clientStat->bytes_recv;
    }
}


/*
 * NAME:        MDPFinalize.
 * PURPOSE:     Collect statistics of a MDP node for the sessions.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void MdpFinalize(Node* node)
{
    char buf[MAX_STRING_LENGTH];
    Int32 sourcePort;
    MdpSession* sessionHandle = NULL;
    MdpSession* oldSessionHandle = NULL;
    MdpData* mdpData = NULL;
    MdpClientStats* totalClientStat = new MdpClientStats;
    MdpCommonStats* totalCommonStats = new MdpCommonStats;

    // init MdpCommonStats and MdpClientStats
    totalCommonStats->Init();
    totalClientStat->Init();

    mdpData = (MdpData*) node->appData.mdp;
    sessionHandle = GetMdpSessionHandleFromSessionMgr(node,
                                                    mdpData->sessionManager);

    if (!sessionHandle)
    {
        return;
    }

    sourcePort = sessionHandle->GetLocalAddr().GetPort();

    while (sessionHandle)
    {
        MdpClientStats & clientStat = sessionHandle->GetMdpClientStats();
        MdpCommonStats & commonStats = sessionHandle->GetMdpCommonStats();

        MdpAddSessionStatsCount(sessionHandle,
                                totalCommonStats,
                                &commonStats,
                                totalClientStat,
                                &clientStat);

        // save current session handle before moving to next
        oldSessionHandle = sessionHandle;

        // move to next session entry
        sessionHandle = sessionHandle->GetNextPointer();

        // close old session and delete it
        oldSessionHandle->Close(true);
        mdpData->sessionManager->DeleteSession(oldSessionHandle);
    }


    sprintf(buf, "Total Number of MDP Sessions = %d", mdpData->totalSession);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total Number of Data Objects Fail"
                 " to Queue = %" TYPES_64BITFMT "u",
                                    totalCommonStats->numDataObjFailToQueue);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);

    sprintf(buf, "Total Number of File Objects Fail"
                 " to Queue = %" TYPES_64BITFMT "u",
                                    totalCommonStats->numFileObjFailToQueue);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);

    sprintf(buf, "Total MDP_CMD Messages Sent = %" TYPES_64BITFMT "u",
                                       totalCommonStats->numCmdMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_CMD Messages Received = %" TYPES_64BITFMT "u",
                                        totalCommonStats->numCmdMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);



    sprintf(buf, "Total MDP_CMD_FLUSH Messages Sent = %" TYPES_64BITFMT "u",
                                  totalCommonStats->numCmdFlushMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_CMD_FLUSH Messages Received "
                 "= %" TYPES_64BITFMT "u",
                                   totalCommonStats->numCmdFlushMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_CMD_SQUELCH Messages Sent = %" TYPES_64BITFMT "u",
                                totalCommonStats->numCmdSquelchMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_CMD_SQUELCH Messages Received "
                 "= %" TYPES_64BITFMT "u",
                                 totalCommonStats->numCmdSquelchMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_CMD_ACK_REQ Messages Sent = %" TYPES_64BITFMT "u",
                                 totalCommonStats->numCmdAckReqMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_CMD_ACK_REQ Messages Received "
                 "= %" TYPES_64BITFMT "u",
                                  totalCommonStats->numCmdAckReqMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_ACK Messages Sent = %" TYPES_64BITFMT "u",
                                    totalCommonStats->numPosAckMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_ACK Messages Received = %" TYPES_64BITFMT "u",
                                     totalCommonStats->numPosAckMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);



    sprintf(buf, "Total MDP_CMD_GRTT_REQ Messages Sent "
                 "= %" TYPES_64BITFMT "u",
                                totalCommonStats->numCmdGrttReqMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_CMD_GRTT_REQ Messages Received "
                 "= %" TYPES_64BITFMT "u",
                                 totalCommonStats->numCmdGrttReqMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total Response Sent for MDP_CMD_GRTT_REQ "
                 "= %" TYPES_64BITFMT "u",
                                   totalCommonStats->numGrttAckMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total Response Received for MDP_CMD_GRTT_REQ "
                 "= %" TYPES_64BITFMT "u",
                                   totalCommonStats->numGrttAckMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_CMD_NACK_ADV Messages Sent "
                 "= %" TYPES_64BITFMT "u",
                                totalCommonStats->numCmdNackAdvMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_CMD_NACK_ADV Messages Received "
                 "= %" TYPES_64BITFMT "u",
                                 totalCommonStats->numCmdNackAdvMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);



    sprintf(buf, "Total MDP_NACK Messages Sent = %" TYPES_64BITFMT "u",
                                      totalCommonStats->numNackMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_NACK Messages Received = %" TYPES_64BITFMT "u",
                                       totalCommonStats->numNackMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);



    sprintf(buf, "Total MDP_NACK Messages Suppressed = %u",
                                                  totalClientStat->supp_cnt);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);



    sprintf(buf, "Total MDP_REPORT Messages Sent = %" TYPES_64BITFMT "u",
                                    totalCommonStats->numReportMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_REPORT Messages Received = %" TYPES_64BITFMT "u",
                                     totalCommonStats->numReportMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_INFO Messages Sent = %" TYPES_64BITFMT "u",
                                      totalCommonStats->numInfoMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_INFO Messages Received = %" TYPES_64BITFMT "u",
                                       totalCommonStats->numInfoMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_DATA Messages Sent = %" TYPES_64BITFMT "u",
                                      totalCommonStats->numDataMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total MDP_DATA Messages Received = %" TYPES_64BITFMT "u",
                                       totalCommonStats->numDataMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);



    sprintf(buf, "Total MDP_PARITY Messages Sent = %" TYPES_64BITFMT "u",
                                    totalCommonStats->numParityMsgSentCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);



    sprintf(buf, "Total MDP_PARITY Messages Received = %" TYPES_64BITFMT "u",
                                    totalCommonStats->numParityMsgRecCount);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total Received MDP Objects Completed = %u",
                                                   totalClientStat->success);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total Received MDP Objects Pending = %u",
                                                    totalClientStat->active);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total Received MDP Objects Failed = %u",
                                                      totalClientStat->fail);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total Number of MDP DATA & PARITY Bytes Sent "
                 "= %" TYPES_64BITFMT "u",
                                           totalCommonStats->totalBytesSent);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total Number of MDP DATA & PARITY Bytes Received = %u",
                                                totalClientStat->bytes_recv);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);



    sprintf(buf,"Total Number of MDP Blocks Received = %u",
                                            totalClientStat->blk_stat.count);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Total Number of Resynchronize with Sender Performed = %u",
                                                    totalClientStat->resync);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);



    sprintf(buf, "Total Number of MDP Block & Vector Pool Overruns = %u",
                                         totalClientStat->buf_stat.overflow);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    sprintf(buf, "Maximum Usage of MDP Block & Vector Pool = %u",
                                             totalClientStat->buf_stat.peak);
    IO_PrintStat(
        node,
        "Application",
        "MDP",
        ANY_DEST,
        sourcePort,
        buf);


    // free memory
    delete totalClientStat;
    delete totalCommonStats;

    // free other mdpData class/stl pointer variables
    if (MDP_DEFAULT_FILE_TEMP_DELETION_ENABLED)
    {
        // delete all temp files created by MDP clients
        if (mdpData->temp_file_cache)
        {
            mdpData->temp_file_cache->Destroy();
            delete mdpData->temp_file_cache;
        }
        mdpData->temp_file_cache = NULL;
    }

    // free mdpCpommonData class pointer
    if (mdpData->mdpCommonData)
    {
        delete mdpData->mdpCommonData;
        mdpData->mdpCommonData = NULL;
    }
    
    // free receivePortList vector
    if (mdpData->receivePortList)
    {
        mdpData->receivePortList->erase(mdpData->receivePortList->begin(),
                                        mdpData->receivePortList->end());
        delete mdpData->receivePortList;
        mdpData->receivePortList = NULL;
    }
        
    //free multimap_MdpSessionList multimap
    if (mdpData->multimap_MdpSessionList)
    {
        std::multimap<Int32,MdpUniqueTuple*,ltcompare_mdpMap1>::iterator
                                                                    iterator;
        for (iterator = mdpData->multimap_MdpSessionList->begin();
             iterator != mdpData->multimap_MdpSessionList->end();
             iterator++)
        {
            if (iterator->second)
            {
                MdpUniqueTuple* uniqueTuple = iterator->second;
                
                // setting session pointer to NULL as it is already freed.
                uniqueTuple->session = NULL;
                MEM_free(iterator->second);
                iterator->second = NULL;
            }
        }
        // now delete multimap
        mdpData->multimap_MdpSessionList->erase(
                                mdpData->multimap_MdpSessionList->begin(),
                                mdpData->multimap_MdpSessionList->end());
        delete mdpData->multimap_MdpSessionList;
        mdpData->multimap_MdpSessionList = NULL;
    }

    //free multimap_MdpSessionListByPort multimap
    if (mdpData->multimap_MdpSessionListByPort)
    {
        std::multimap<UInt16,MdpSession*,ltcompare_mdpMap2>::iterator
                                                                    iterator;
        for (iterator = mdpData->multimap_MdpSessionListByPort->begin();
             iterator != mdpData->multimap_MdpSessionListByPort->end();
             iterator++)
        {
            if (iterator->second)
            {                
                // setting session pointer to NULL as it is already freed
                iterator->second = NULL;
            }
        }
        // now delete multimap
        mdpData->multimap_MdpSessionListByPort->erase(
                            mdpData->multimap_MdpSessionListByPort->begin(),
                            mdpData->multimap_MdpSessionListByPort->end());
        delete mdpData->multimap_MdpSessionListByPort;
        mdpData->multimap_MdpSessionListByPort = NULL;
    }
}



/*
 * NAME:        MdpLayerInit.
 * PURPOSE:     Init MDP layer for the called unicast/multicast applications
 * PARAMETERS:  node - pointer to the node which received the message.
 *              clientAddr - specify address of the sender node
 *                           i.e. local address.
 *              serverAddr - specify address of the receiver
 *                           i.e. destination address.
 *              sourcePort - source port of the sender.
 *              appType - application type for sender, for which MDP layer
 *                           is going to be initialize.
 *              isProfileNameSet - TRUE is MDP profile is defined.
 *                           Default value is FALSE.
 *              profileName - the profile name if "isProfileNameSet" is TRUE.
 *                           Default value is NULL.
 *              uniqueId - unique id for MDP session. Default value is -1.
 *              nodeInput - pointer to NodeInput. Default value is NULL.
 *              destPort - destination port of the receiver.
 *              destIsUnicast - whether dest address is unicast address.
 *                           Default value is FALSE.
 * RETURN:      void.
 */
void MdpLayerInit(Node* node,
                  Address clientAddr,
                  Address serverAddr,
                  Int32 sourcePort,
                  AppType appType,
                  BOOL isProfileNameSet,
                  char* profileName,
                  Int32 uniqueId,
                  const NodeInput* nodeInput,
                  Int32 destPort,
                  BOOL destIsUnicast)
{
    // first check for APP_FORWARD application
    if (appType == APP_FORWARD)
    {
        MdpLayerInitForAppForward(node,
                                 clientAddr,
                                 serverAddr,
                                 sourcePort,
                                 appType,
                                 uniqueId);

        // simply return to avoid any further processing in this function
        return;
    }
    
    // if the called application is not APP_FORWARD
    // then below code need to be executed    
    char* token = NULL;
    char* next = NULL;
    char delims[] = {" \t"};
    char iotoken[MAX_STRING_LENGTH];
    char errStr[MAX_STRING_LENGTH];
    char tempStr[MAX_STRING_LENGTH];
    char mcastMemberString[MAX_STRING_LENGTH];
    char mcastAddrString[MAX_STRING_LENGTH];
    Address mcastNodeAddr;
    Address mcastAddr;
    NodeId mcastMemNodeId;
    NodeId v6NodeId;
    BOOL isNodeId;
    BOOL retVal = FALSE;
    BOOL found = FALSE;
    Int32 i = 0;
    Int32 j = 0;
    NodeInput profileInput;
    NodeInput memberInput;
    Node* mcastNode;
    MdpSession* theSession = NULL;
    MdpCommonParameters mdpCommonData;
    MdpCommonParameters* passCommonData;

    // MDP node data initialization
    MdpInit(node, nodeInput);

    MdpData* mdpData = (MdpData*) node->appData.mdp;
    // assign passCommonData with global level mdpCommonData
    passCommonData = mdpData->mdpCommonData;

    if (isProfileNameSet)
    {

        MdpInitOptParamWithDefaultValues(node,
                                         &mdpCommonData,
                                         nodeInput);

        IO_ReadCachedFile(node->nodeId,
                          ANY_ADDRESS,
                          nodeInput,
                          "MDP-PROFILE-FILE",
                          &retVal,
                          &profileInput);

        if (retVal == FALSE)
        {
            sprintf(errStr,"MDP: Needs MDP-PROFILE-FILE "
                           "for profile name %s.\n",profileName);

            ERROR_ReportError(errStr);
        }

        for (i = 0; i < profileInput.numLines; i++)
        {
            token = IO_GetDelimitedToken(iotoken,
                                         profileInput.inputStrings[i],
                                         delims,
                                         &next);

            if (!token ||(strcmp(token,"MDP-PROFILE")!= 0))
            {
                continue;
            }

            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (token && strcmp(token,profileName) == 0)
            {
                found = TRUE;
                for (j = i + 1; j < profileInput.numLines; j++)
                {
                    sscanf(profileInput.inputStrings[j],"%s",tempStr);
                    if (strcmp(tempStr,"MDP-PROFILE") == 0)
                    {
                        break;
                    }
                    MdpInitializeOptionalParameters(node,
                                             profileInput.inputStrings[j],
                                             &mdpCommonData);
                }
            }
            else
            {
                continue;
            }

            if (found == TRUE)
            {
                break;
            }
        }
        if (!found)
        {
            std::stringstream errorStr;
            errorStr << "MDP profile ";
            errorStr << profileName;
            errorStr << " not found in profile file ";
            errorStr << profileInput.ourName; 
            errorStr << " at node ";
            errorStr << node->nodeId;
            errorStr << " Continue with default values. \n";
            ERROR_ReportWarning(errorStr.str().c_str());
        }
        else
        {
        // preference for mdpCommonData defined by MDP-PROFILE in ".app"
        passCommonData = &mdpCommonData;
        }
    }// end of if (isProfileNameSet)

    theSession = MdpFindSessionInList(node,clientAddr,serverAddr,uniqueId);

    if (theSession)
    {
        sprintf(errStr, "MDP Session already present for the sender node %d "
                        "at the time of MDP layer init. \n",
                        node->nodeId);
        ERROR_ReportError(errStr);
    }
    // MDP init for session manager and session for sender node
    theSession = MdpNewSessionInit(node,
                                  clientAddr,
                                  serverAddr,
                                  uniqueId,
                                  sourcePort,
                                  appType,
                                  passCommonData);

    if (destPort == -1)
    {
        // resetting sourceport with server address
        theSession->SetAddr(MdpGetProtoAddress(serverAddr,
                           (UInt16)MdpGetAppTypeForServer(appType)));
    }
    else
    {
        theSession->SetAddr(MdpGetProtoAddress(serverAddr,
                                                  (UInt16)destPort));
    }
    // adding unique entry for session in the MdpUniqueTupleList
    MdpAddSessionInList(node,
                        clientAddr,
                        serverAddr,
                        uniqueId,
                        theSession);

    if (!destIsUnicast)
    {
        // Now do server init for the nodes in the multicast group
        retVal = FALSE;

        IO_ReadCachedFile(ANY_NODEID,
                          ANY_ADDRESS,
                          nodeInput,
                          "MULTICAST-GROUP-FILE",
                          &retVal,
                          &memberInput);

        if (retVal == FALSE)
        {
            ERROR_ReportWarning("MULTICAST-GROUP-FILE is missing.\n");
        }
        else
        {
            for (j = 0; j < memberInput.numLines; j++)
            {
                sscanf(memberInput.inputStrings[j],
                            "%s %s",
                            mcastMemberString, mcastAddrString);

                if (MAPPING_GetNetworkType(mcastAddrString) == NETWORK_IPV6)
                {
                    mcastAddr.networkType = NETWORK_IPV6;

                    IO_ParseNodeIdOrHostAddress(
                        mcastAddrString,
                        &mcastAddr.interfaceAddr.ipv6,
                        &v6NodeId);
                }
                else
                {
                    mcastAddr.networkType = NETWORK_IPV4;

                    IO_ParseNodeIdOrHostAddress(
                        mcastAddrString,
                        &mcastAddr.interfaceAddr.ipv4,
                        &isNodeId);
                }

               if (mcastAddr.networkType == NETWORK_IPV4)
               {
                   if (!(GetIPv4Address(mcastAddr) >=
                                               IP_MIN_MULTICAST_ADDRESS))
                   {
                        sprintf(errStr, "MDP: multicast address is not a "
                             "valid group address\n");
                        ERROR_ReportError(errStr);
                   }
               }
               else
               {
                    if (!IS_MULTIADDR6(GetIPv6Address(mcastAddr)))
                    {
                        sprintf(errStr, "MDP: multicast address is not a "
                             "valid group address\n");
                        ERROR_ReportError(errStr);
                    }
                    else if (!Ipv6IsValidGetMulticastScope(
                                node,
                                GetIPv6Address(mcastAddr)))
                    {
                        sprintf(errStr, "MDP: multicast address is not a "
                             "valid group address\n");
                        ERROR_ReportError(errStr);
                    }
                }

                IO_AppParseSourceString(
                    node,
                    memberInput.inputStrings[j],
                    mcastMemberString,
                    &mcastMemNodeId,
                    &mcastNodeAddr,
                    mcastAddr.networkType);


                mcastNode = MAPPING_GetNodePtrFromHash(
                                             node->partitionData->nodeIdHash,
                                             mcastMemNodeId);

                if (mcastNode != NULL)
                {
                    // checking whether the node lies in the same group
                    if (Address_IsSameAddress(&mcastAddr,&serverAddr))
                    {
                        // MDP node data initialization
                        MdpInit(mcastNode, nodeInput);
                    }
                }// if (mcastNode != NULL)
            }// for (j = 0; j < memberInput.numLines; j++)
        }
    }// if (!destIsUnicast)
}



/*
 * NAME:        MdpLayerInitForAppForward.
 * PURPOSE:     Init MDP layer for APP_FORWARD
 * PARAMETERS:  node - pointer to the node which received the message.
 *              clientAddr - local address
 *              serverAddr - destination address
 *              sourcePort - sender source port
 *              appType - AppType for sender
 *              uniqueId - APP_FORWARD unique id with respect to application.
 * RETURN:      none.
 */
void MdpLayerInitForAppForward(Node* node,
                  Address clientAddr,
                  Address serverAddr,
                  Int32 sourcePort,
                  AppType appType,
                  Int32 uniqueId)
{
    char errStr[MAX_STRING_LENGTH];
    MdpSession* theSession = NULL;
    Int32 mdpUniqueId;

    MdpData* mdpData = (MdpData*) node->appData.mdp;

    if (!mdpData)
    {
        sprintf(errStr, "MDP is not initialized at node level for node %d",
                        node->nodeId);
        ERROR_ReportError(errStr);
    }

    mdpUniqueId = mdpData->maxAppLines + 10 + uniqueId;

    theSession = MdpFindSessionInList(node,
                                      clientAddr,
                                      serverAddr,
                                      mdpUniqueId);
    if (theSession)
    {
        sprintf(errStr, "MDP Session already present for the sender node %d "
                        "at the time of MDP layer init. \n",
                        node->nodeId);
        ERROR_ReportWarning(errStr);
    }
    else
    {
        // MDP init for session manager and session for sender node
        theSession = MdpNewSessionInit(node,
                                      clientAddr,
                                      serverAddr,
                                      mdpUniqueId,
                                      sourcePort,
                                      appType,
                                      mdpData->mdpCommonData);

        // resetting sourceport with server address
        theSession->SetAddr(MdpGetProtoAddress(serverAddr,
                                        (UInt16)APP_FORWARD));
        // adding unique entry for session in the MdpUniqueTupleList
        MdpAddSessionInList(node,
                            clientAddr,
                            serverAddr,
                            mdpUniqueId,
                            theSession);
    }
}


/*
 * NAME:        MdpReadProfileFromApp.
 * PURPOSE:     Return TRUE if MDP profile defined in .app file found
 * PARAMETERS:  node - pointer to the node.
 *              uniqueId - Mdp unique id with respect to application.
 *              mdpCommonData - pointer to MdpCommonParameters
 * RETURN:      BOOL.
 */
BOOL MdpReadProfileFromApp(Node* node,
                           Int32 uniqueId,
                           MdpCommonParameters* mdpCommonData)
{
    if (uniqueId == -1)
    {
        return FALSE;
    }

    Int32 appLineNumber = uniqueId - 1;
    const NodeInput* nodeInput = node->partitionData->nodeInput;
    BOOL retVal = FALSE;
    BOOL found = FALSE;
    BOOL profileFound = FALSE;
    NodeInput appInput;
    NodeInput profileInput;
    Int32 i;
    Int32 j;
    Int32 k;

    IO_ReadCachedFile(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "APP-CONFIG-FILE",
        &retVal,
        &appInput);

    if (retVal == FALSE)
    {
        return FALSE;
    }

    for (i = 0; i < appInput.numLines; i++)
    {
        if (i == appLineNumber)
        {
            char* token = NULL;
            char* next = NULL;
            char delims[] = {" ,\t"};
            char iotoken[MAX_STRING_LENGTH];
            char errStr[MAX_STRING_LENGTH];
            char tempStr[MAX_STRING_LENGTH];
            char profileName[MAX_STRING_LENGTH] = "/0";
            BOOL isProfileNameSet = FALSE;

            char* optionTokens = appInput.inputStrings[i];

            token = IO_GetDelimitedToken(iotoken,optionTokens,delims,&next);

            while (token)
            {
                if (strcmp(token,"MDP-PROFILE")== 0)
                {
                    isProfileNameSet = TRUE;

                    token = IO_GetDelimitedToken(iotoken,next,delims,&next);
                    if (token)
                    {
                        sprintf(profileName, "%s", token);
                        profileFound = TRUE;
                    }
                    break;
                }
                token = IO_GetDelimitedToken(iotoken, next, delims, &next);
            }// while (token)

            if (profileFound)
            {
                retVal = FALSE;

                IO_ReadCachedFile(node->nodeId,
                                  ANY_ADDRESS,
                                  nodeInput,
                                  "MDP-PROFILE-FILE",
                                  &retVal,
                                  &profileInput);

                if (retVal == FALSE)
                {
                    sprintf(errStr,"MDP: Needs MDP-PROFILE-FILE "
                                   "for profile name %s.\n",profileName);

                    ERROR_ReportError(errStr);
                }

                // init with default values
                MdpInitOptParamWithDefaultValues(node,
                                                 mdpCommonData,
                                                 nodeInput);

                for (j = 0; j < profileInput.numLines; j++)
                {
                    token = IO_GetDelimitedToken(iotoken,
                                                profileInput.inputStrings[j],
                                                delims,
                                                &next);

                    if (!token ||(strcmp(token,"MDP-PROFILE")!= 0))
                    {
                        continue;
                    }

                    token = IO_GetDelimitedToken(iotoken,next,delims,&next);

                    if (token && strcmp(token,profileName) == 0)
                    {
                        found = TRUE;
                        for (k = j + 1; k < profileInput.numLines; k++)
                        {
                           sscanf(profileInput.inputStrings[k],"%s",tempStr);
                           if (strcmp(tempStr,"MDP-PROFILE") == 0)
                           {
                               break;
                           }
                           MdpInitializeOptionalParameters(node,
                                                profileInput.inputStrings[k],
                                                mdpCommonData);
                        }
                    }
                    else
                    {
                        continue;
                    }

                    if (found == TRUE)
                    {
                        break;
                    }
                }// for (j = 0; j < profileInput.numLines; j++)
                if (!found)
                {
                    std::stringstream errorStr;
                    errorStr << "MDP profile ";
                    errorStr << profileName;
                    errorStr << " not found in profile file ";
                    errorStr << profileInput.ourName; 
                    errorStr << " at node ";
                    errorStr << node->nodeId;
                    errorStr << " Continue with default values. \n";
                    ERROR_ReportWarning(errorStr.str().c_str());

                    return FALSE;
                }
                else
                {
                    return TRUE;
                }
            }// if (profileFound)
            else
            {
                return FALSE;
            }
        }// if (i == appLineNumber)
    }// for (i = 0; i < appInput.numLines; i++)

    return FALSE;
}


/*
 * NAME:        GetMdpSessionHandleFromSessionMgr.
 * PURPOSE:     Reterving session list available at node level
 * PARAMETERS:  node - pointer to the node.
 *              sessionMgr - pointer to the class MdpSessionMgr.
 * RETURN:      pointer to first MdpSession in the list else NULL.
 */
MdpSession*
GetMdpSessionHandleFromSessionMgr(Node* node, MdpSessionMgr* sessionMgr)
{
    if (!sessionMgr)
    {
        return NULL;
    }

    MdpSession* sessionHandle = sessionMgr->GetSessionListHead();

    if (!sessionHandle)
    {
        return NULL;
    }
    else
    {
        return sessionHandle;
    }
}



/*
 * NAME:        MdpSendDataToApp.
 * PURPOSE:     Send received data objects by MDP to application receiver.
 *              In case of file object it sends notification.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              info - UdpToAppRecv info of the received Message
 *              data - packet data
 *              objectSize - complete object size
 *              actualObjectSize - object size without virtual payload
 *              theMsgPtr - pointer to the Message
 *              objectType - Mdp object type data or file.
 *              objectInfo - Mdp object info if any
 *              objectInfoSize - Mdp object info size
 *              theSession - Mdp Session pointer
 * RETURN:      none.
 */
void MdpSendDataToApp(Node* node,
                      char* infoUdpToAppRecv,
                      char* data,
                      AppType appType,
                      Int32 objectSize,
                      Int32 actualObjectSize,
                      Message* theMsgPtr,
                      MdpObjectType objectType,
                      char* objectInfo,
                      Int32 objectInfoSize,
                      MdpSession* theSession)
{
    Message* msg = NULL;
    MdpPersistentInfo* mdpInfo = NULL;
    Int32 packetSize = 0;
    TraceProtocolType traceType = TRACE_UNDEFINED;
    Int16 protocolType = 0;
    char traceErrStr[MAX_STRING_LENGTH];

    mdpInfo = (MdpPersistentInfo*) MESSAGE_ReturnInfo(theMsgPtr,
                                              INFO_TYPE_MdpInfoData);

    if (mdpInfo && mdpInfo->virtualSize > 0)
    {
        packetSize = objectSize - mdpInfo->virtualSize;
    }
    else
    {
        packetSize = objectSize;
    }

    if (packetSize != actualObjectSize)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "(packetSize != actualObjectSize) comes out in "
                "function MdpSendDataToApp(). Need to check the problem \n");
        ERROR_ReportWarning(errStr);
    }

    msg = MESSAGE_Alloc(node,
                        APP_LAYER,
                        appType,
                        MSG_APP_FromTransport);

    // get actual protocol type if port is EXata Incoming port
    Int16 destPortNumber = 0;

    if (mdpInfo)
    {
        destPortNumber = mdpInfo->destPort;
    }
    else
    {
        destPortNumber = ((UdpToAppRecv*)infoUdpToAppRecv)->destPort;
    }

    if (MdpIsExataIncomingPort(node, destPortNumber))
    {
        protocolType = APP_GetProtocolType(node, msg);
        // change the msg protocol type
        msg->protocolType = protocolType;
        // now get the trace type
        traceType = MdpGetTraceProtocolForAppType((AppType)protocolType);

        if (traceType == TRACE_UNDEFINED)
        {
            sprintf(traceErrStr, "No application protocol found running "
                                 "on EXata mapped MDP port number %d. "
                                 "Hence discarding the received "
                                 "packet. \n",
                                 destPortNumber);
        }
    }
    else
    {
        traceType = MdpGetTraceProtocolForAppType(appType);

        if (traceType == TRACE_UNDEFINED)
        {
            sprintf(traceErrStr, "TraceProtocolType not found for "
                                 "AppType %d. Hence discarding the "
                                 "received packet. \n",
                                 appType);
        }
    }

    if (traceType == TRACE_UNDEFINED)
    {
        // changing the receiverApp status, which was assumed to be
        // TRUE while creating the session
        theSession->SetReceiverAppExistStatus(FALSE);

        // print warning message
        ERROR_ReportWarning(traceErrStr);

        // Free message and simply return.
        MESSAGE_Free(node, msg);
        return;
    }

    if (packetSize > 0)
    {
        MESSAGE_PacketAlloc(node,
                            msg,
                            packetSize,
                            traceType);

        memcpy(MESSAGE_ReturnPacket(msg), data, packetSize);
    }

    // Add virtual data if present
    if (mdpInfo && mdpInfo->virtualSize > 0)
    {
        MESSAGE_AddVirtualPayload(node, msg, mdpInfo->virtualSize);
    }

    // Copy info fields of the original message.
    if (theMsgPtr != NULL)
    {
        if (theMsgPtr->infoArray.size() > 0)
        {
            // Copy the info fields.
            MESSAGE_CopyInfo(node, msg, theMsgPtr);
        }
    }

    // adding persistant info INFO_TYPE_MdpObjectInfo if objectInfo exist
    if (objectInfoSize > 0)
    {
        MdpPersistentObjectInfo mdpObjectInfo;

        mdpObjectInfo.objectType = objectType;
        mdpObjectInfo.objectInfoSize = objectInfoSize;

        char *mdpInfoObject = NULL;
        mdpInfoObject = MESSAGE_AddInfo(node,
                                      msg,
                                      (sizeof(MdpPersistentObjectInfo)
                                      + sizeof(char)*objectInfoSize+1),
                                      INFO_TYPE_MdpObjectInfo);

        memset(mdpInfoObject, 0, (sizeof(MdpPersistentObjectInfo)
                                      + sizeof(char)*objectInfoSize+1));
        memcpy(mdpInfoObject,
               &mdpObjectInfo,
               sizeof(MdpPersistentObjectInfo));

        mdpInfoObject = mdpInfoObject + sizeof(MdpPersistentObjectInfo);
        memcpy(mdpInfoObject, objectInfo, objectInfoSize);
    }

    // now tackle UDP info
    MESSAGE_InfoAlloc(node, msg, sizeof(UdpToAppRecv));

    UdpToAppRecv* infoPtr = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);

    memcpy(infoPtr, infoUdpToAppRecv, sizeof(UdpToAppRecv));

    // infoPtr->destPort = (Int16)MdpGetAppTypeForServer(appType);

    if (mdpInfo)
    {
        infoPtr->destPort = (Int16)mdpInfo->destPort;
        
        // removing persistent info related to INFO_TYPE_MdpInfoData
        MESSAGE_RemoveInfo(node, msg, INFO_TYPE_MdpInfoData);
    }

#ifdef ADDON_DB
    // retrieve original message ID
    StatsDBTrimMessageMsgId(node, msg, 'T');
#endif

    MESSAGE_Send(node, msg, 0);
}


/*
 * NAME:        MdpGetProtoAddress.
 * PURPOSE:     Conversion function from Address to MdpProtoAddress
 * PARAMETERS:  addr - address.
 *              port - source port
 * RETURN:      MdpProtoAddress.
 */
MdpProtoAddress MdpGetProtoAddress(Address addr, UInt16 port)
{
    MdpProtoAddress pAddr;
    pAddr.SetAddress(addr);
    pAddr.PortSet(port);
    return pAddr;
}


/*
 * FUNCTION:   MdpIsExataIncomingPort
 * PURPOSE:    Used to verify whether port is MDP EXata incoming port
 * PARAMETERS: node - node pointer.
 *             port - port id that needs to be verify.
 * RETURN:     BOOL.
 */
BOOL MdpIsExataIncomingPort(Node* node,
                            UInt16 port)
{
    BOOL isPortFound = FALSE;
    if (node->appData.mdp)
    {
        MdpData* mdpData = (MdpData*) node->appData.mdp;

        for (Int32 i = 0; i < (Int32)mdpData->receivePortList->size(); i++)
        {
            if ((*mdpData->receivePortList)[i] == port)
            {
                isPortFound = TRUE;
                break;
            }
        }

        if (isPortFound)
        {
            return TRUE;
        }
    }
    else
    {
        return FALSE;
    }
    return FALSE;
}


/*
 * FUNCTION:   MdpAddPortInExataIncomingPortList
 * PURPOSE:    Used to add port in MDP EXata incoming port list if not exist
 * PARAMETERS: node - node pointer.
 *             port - port id that needs to be added.
 * RETURN:     BOOL.
 */
BOOL MdpAddPortInExataIncomingPortList(Node* node,
                                       UInt16 port)
{
    BOOL isPortFound = FALSE;
    if (node->appData.mdp)
    {
        MdpData* mdpData = (MdpData*) node->appData.mdp;

        for (Int32 i = 0; i < (Int32)mdpData->receivePortList->size(); i++)
        {
            if ((*mdpData->receivePortList)[i] == port)
            {
                isPortFound = TRUE;
                break;
            }
        }

        if (!isPortFound)
        {
            mdpData->receivePortList->push_back(port);
            return TRUE;
        }
    }
    else
    {
        return FALSE;
    }
    return FALSE;
}


/*
 * FUNCTION:   MdpAddPortInExataOutPortList
 * PURPOSE:    Used to add port and ipaddress pair in MDP EXata out port list
 *             if not exist for EXata node. This list is required to
 *             handle ACK, NACK, REPORT unicast reply
 * PARAMETERS: node - node pointer.
 *             port - port id that needs to be added.
 *             ipAddress - IP address that needs to be verify
 * RETURN:     BOOL.
 */
BOOL MdpAddPortInExataOutPortList(Node* node,
                                  UInt16 port,
                                  NodeAddress ipAddress)
{
    if (node->appData.mdp)
    {
        MdpData* mdpData = (MdpData*) node->appData.mdp;

        if (!mdpData->outPortList)
        {
            // need to allocate the list
            mdpData->outPortList =
                new std::vector <std::pair<UInt16, NodeAddress> >(0);
        }

        std::vector <std::pair<UInt16, NodeAddress> >::iterator iter;

        iter = std::find(mdpData->outPortList->begin(),
                         mdpData->outPortList->end(),
                         std::make_pair(port,ipAddress));

        if (iter != mdpData->outPortList->end())
        {
            // entry already exist, do nothing
            return FALSE;
        }
        else
        {
            // add this entry
            mdpData->outPortList->push_back(std::make_pair(port,ipAddress));
            return TRUE;
        }
    }
    else
    {
        return FALSE;
    }
}



/*
 * FUNCTION:   MdpIsExataPortInOutPortList
 * PURPOSE:    Used to verify whether port and ipAddress pair is in MDP
 *             EXata Out portlist
 * PARAMETERS: node - node pointer.
 *             port - port id that needs to be verify.
 *             ipAddress - IP address that needs to be verify
 * RETURN:     BOOL.
 */
BOOL MdpIsExataPortInOutPortList(Node* node,
                                 UInt16 port,
                                 NodeAddress ipAddress)
{
    if (node->appData.mdp)
    {
        MdpData* mdpData = (MdpData*) node->appData.mdp;

        if (!mdpData->outPortList)
        {
            return FALSE;
        }

        std::vector <std::pair<UInt16, NodeAddress> >::iterator iter;

        iter = std::find(mdpData->outPortList->begin(),
                         mdpData->outPortList->end(),
                         std::make_pair(port,ipAddress));

        return (iter != mdpData->outPortList->end());
    }
    else
    {
        return FALSE;
    }
}



/*
 * FUNCTION:   MdpIsServerPacket
 * PURPOSE:    Used to verify whether the packet is from MDP sender
 * PARAMETERS: node - node pointer.
 *             msg - message pointer.
 * RETURN:     BOOL.
 */
BOOL MdpIsServerPacket(Node* node, Message* theMsg)
{
    MdpMessage msg;
    UInt32 len = 0;
    unsigned char* buffer = (unsigned char *)MESSAGE_ReturnPacket(theMsg);
    BOOL isServerMsg = TRUE;

    // common fields first.
    msg.type = (unsigned char) buffer[len++];

    switch (msg.type)
    {
        case MDP_REPORT:
        {
            isServerMsg = FALSE;
            break;
        }
        case MDP_NACK:
        {
            isServerMsg = FALSE;
            break;
        }
        case MDP_ACK:
        {
            isServerMsg = FALSE;
            break;
        }
        default:
        {
            // do nothing
        }
    }

    return isServerMsg;
}



/*
 * FUNCTION:   MdpSwapIncomingPacketForNtoh
 * PURPOSE:    Used to do ntoh for MDP external incoming packets which
 *             are escaped through mdp_interface.cpp
 * PARAMETERS: node - node pointer.
 *             msg - message pointer.
 * RETURN:     BOOL.
 */
void MdpSwapIncomingPacketForNtoh(Node* node, Message* theMsg)
{
    MdpMessage msg;
    register UInt32 len = 0;
    Int32 count = 0;
    unsigned char* buffer = (unsigned char*)MESSAGE_ReturnPacket(theMsg);
    Int32 size = theMsg->packetSize;
    BOOL isClientMsg = FALSE;

    // Packet in network byte order, so first have to convert in host byte.

    // common fields first.
    msg.type = (unsigned char) buffer[len++];
    msg.version = (unsigned char) buffer[len++];

    EXTERNAL_ntoh(&buffer[2], sizeof(UInt32));  //UInt32 sender
    len += sizeof(UInt32);

    // Now unpack fields unique to message type
    switch (msg.type)
    {
        case MDP_REPORT:
        {
            if (MDP_DEBUG)
            {
                printf("MdpSwapIncomingPacketForNtoh(): "
                       "Receiving MDP_REPORT\n");
            }
            isClientMsg = TRUE;
            msg.report.status = (unsigned char) buffer[len++];
            msg.report.flavor = (unsigned char) buffer[len++];
            switch (msg.report.flavor)
            {
                case MDP_REPORT_HELLO:
                {
                    // skip field report.node_name
                    //strncpy(report.node_name,
                    //          &buffer[len],
                    //          MDP_NODE_NAME_MAX);
                    len += MDP_NODE_NAME_MAX;                              // for report.node_name
                    if (msg.report.status & MDP_CLIENT)
                    {
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for duration
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for success
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for active
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for fail
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for resync
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.count
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_00
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_05
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_10
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_20
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_40
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_50
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for tx_rate
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for nack_cnt
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for supp_cnt
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for buf_stat.buf_total
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for buf_stat.peak
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for buf_stat.overflow
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for goodput
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for rx_rate
                        len += sizeof(UInt32);
                    }
                    break;
                }
                default:
                {
                    if (MDP_DEBUG)
                    {

                        printf("MdpSwapIncomingPacketForNtoh(): "
                               "Invalid report type! %u\n",
                               msg.report.flavor);
                    }
                }
            }
            break;
        }
        case MDP_INFO:
        {
            if (MDP_DEBUG)
            {
                printf("MdpSwapIncomingPacketForNtoh(): "
                       "Receiving MDP_INFO\n");
            }
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for object.sequence
            len += sizeof(UInt16);
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_id
            len += sizeof(UInt32);
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_size
            len += sizeof(UInt32);
            
            // skipping 4 bytes for object.ndata,
            // object.nparity, object.flags, and object.grtt
            len += 4;
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for object.info.segment_size
            len += sizeof(UInt16);
            break;
        }
        case MDP_DATA:
        {
            if (MDP_DEBUG)
            {
                printf("MdpSwapIncomingPacketForNtoh(): "
                       "Receiving MDP_DATA\n");
            }
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for object.sequence
            len += sizeof(UInt16);
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_id
            len += sizeof(UInt32);
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_size
            len += sizeof(UInt32);

            // skipping 2 bytes for object.ndata, and object.nparity
            len += 2;
            msg.object.flags = (unsigned char)buffer[len++];   // for object.flags
            len++;                                             // for object.grtt
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.data.offset
            len += sizeof(UInt32);

            if (msg.object.flags & MDP_DATA_FLAG_RUNT)
            {
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));   // for object.data.segment_size
                len += sizeof(UInt16);
            }
            break;
        }
        case MDP_PARITY:
        {
            if (MDP_DEBUG)
            {
                printf("MdpSwapIncomingPacketForNtoh(): "
                       "Receiving MDP_PARITY\n");
            }
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for object.sequence
            len += sizeof(UInt16);
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_id
            len += sizeof(UInt32);
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_size
            len += sizeof(UInt32);
            
            // skipping 4 bytes for object.ndata,
            // object.nparity, object.flags, and object.grtt
            len += 4;
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.parity.offset
            len += sizeof(UInt32);
            break;
        }
        case MDP_CMD:
        {
            if (MDP_DEBUG)
            {
                printf("MdpSwapIncomingPacketForNtoh(): "
                       "Receiving MDP_CMD\n");
            }
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for cmd.sequence
            len += sizeof(UInt16);
            len++;                                             // for cmd.grtt
            msg.cmd.flavor = (unsigned char)buffer[len++];

            switch (msg.cmd.flavor)
            {
                case MDP_CMD_FLUSH:
                {
                    if (MDP_DEBUG)
                    {
                        printf("MdpSwapIncomingPacketForNtoh(): "
                               "Receiving MDP_CMD_FLUSH\n");
                    }
                    len++;                                      // for cmd.flush.flags
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.flush.object_id
                    len += sizeof(UInt32);
                    break;
                }
                case MDP_CMD_SQUELCH:
                {
                    if (MDP_DEBUG)
                    {
                        printf("MdpSwapIncomingPacketForNtoh(): "
                               "Receiving MDP_CMD_SQUELCH\n");
                    }
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.squelch.sync_id
                    len += sizeof(UInt32);
                    // for cmd.squelch.data
                    unsigned char* squelchPtr = &buffer[len];
                    unsigned char* squelchEnd = squelchPtr +
                                                         (size - (Int32)len);
                    while (squelchPtr < squelchEnd)
                    {
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));
                        squelchPtr += sizeof(UInt32);
                        len += sizeof(UInt32);
                    }
                    break;
                }
                case MDP_CMD_ACK_REQ:
                {
                    if (MDP_DEBUG)
                    {
                        printf("MdpSwapIncomingPacketForNtoh(): "
                               "Receiving MDP_CMD_ACK_REQ\n");
                    }
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.ack_req.object_id
                    len += sizeof(UInt32);
                    // rest is data, unpack them for ack node ids
                    count = 0;
                    unsigned char* ptr = &buffer[len];
                    while (count < (size - (Int32)len))
                    {
                        EXTERNAL_ntoh(&ptr[count], sizeof(UInt32)); // for nodeId
                        count += sizeof(UInt32);
                    }
                    break;
                }
                case MDP_CMD_GRTT_REQ:
                {
                    if (MDP_DEBUG)
                    {
                        printf("MdpSwapIncomingPacketForNtoh(): "
                               "Receiving MDP_CMD_GRTT_REQ\n");
                    }
                    // skipping 2 bytes for cmd.grtt_req.flags,
                    // and cmd.grtt_req.sequence
                    len += 2;
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.send_time.tv_sec
                    len += sizeof(UInt32);
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.send_time.tv_usec
                    len += sizeof(UInt32);
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.hold_time.tv_sec
                    len += sizeof(UInt32);
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.hold_time.tv_usec
                    len += sizeof(UInt32);
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));// for cmd.grtt_req.segment_size
                    len += sizeof(UInt16);
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.grtt_req.rate
                    len += sizeof(UInt32);
                    len++;                                      // for cmd.grtt_req.rtt
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));// for cmd.grtt_req.loss
                    len += sizeof(UInt16);
                    // rest is data, unpack them for representative node ids
                    count = 0;
                    unsigned char* ptr = &buffer[len];
                    while (count < (size - (Int32)len))
                    {
                        EXTERNAL_ntoh(&ptr[count], sizeof(UInt32)); // for repId
                        count += sizeof(UInt32);
                        count++;                                    // for repRtt
                    }
                    break;
                }
                case MDP_CMD_NACK_ADV:
                {
                    if (MDP_DEBUG)
                    {
                        printf("MdpSwapIncomingPacketForNtoh(): "
                               "Receiving MDP_CMD_NACK_ADV\n");
                    }
                    // for cmd.nack_adv.data
                    // Unpack the concatenated Object/Repair Nacks
                    char* optr = (char*)&buffer[len];
                    char* nack_end = optr + (size - (Int32)len);
                    while (optr < nack_end)
                    {
                        MdpObjectNack onack;
                        count = 0;
                        EXTERNAL_ntoh(&optr[count], sizeof(UInt32));  // for object_id
                        count += sizeof(UInt32);
                        EXTERNAL_ntoh(&optr[count], sizeof(UInt16));  // for nack_len
                        memcpy(&onack.nack_len,
                               &optr[count],
                               sizeof(UInt16));
                        count += sizeof(UInt16);
                        // rest is data, so increasing the count with nack_len
                        onack.data = &optr[count];
                        count += onack.nack_len;
                        // and increasing the optr for next Object Nack
                        optr += count;

                        // Now Unpack the concatenated Repair Nacks
                        char* rptr = onack.data;
                        char* onack_end = rptr + onack.nack_len;
                        MdpRepairNack rnack;

                        while (rptr < onack_end)
                        {
                            count = 0;
                            rnack.type = (MdpRepairType) rptr[count++];

                            switch (rnack.type)
                            {
                                case MDP_REPAIR_OBJECT:
                                case MDP_REPAIR_INFO:
                                    break;
                                case MDP_REPAIR_SEGMENTS:
                                    rnack.nerasure =
                                            (unsigned char)rptr[count++];
                                case MDP_REPAIR_BLOCKS:
                                    EXTERNAL_ntoh(&rptr[count],
                                                  sizeof(UInt32));  // for offset
                                    count += sizeof(UInt32);
                                    EXTERNAL_ntoh(&rptr[count],
                                                  sizeof(UInt16));
                                    memcpy(&rnack.mask_len,
                                           &rptr[count],
                                           sizeof(UInt16));
                                    count += sizeof(UInt16);
                                    // rest is mask, so increasing the
                                    // count with mask_len
                                    rnack.mask = &rptr[count];
                                    count += rnack.mask_len;
                                    break;
                                default:
                                    if (MDP_DEBUG)
                                    {
                                        printf("MdpSwapIncomingPacketForNtoh():: "
                                               "Invalid repair nack!\n");
                                    }
                                    // this shouldn't happen
                            }
                            // increase the rptr for next Repair Nack
                            rptr += count;
                        }
                    }
                    break;
                }
                default:
                {
                    if (MDP_DEBUG)
                    {
                        printf("MdpSwapIncomingPacketForNtoh(): "
                               "Invalid MDP_CMD type!\n");
                    }
                }
            }
            break;
        }
        case MDP_NACK:
        {
            if (MDP_DEBUG)
            {
                printf("MdpSwapIncomingPacketForNtoh(): "
                       "Receiving MDP_NACK\n");
            }
            isClientMsg = TRUE;
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for nack.server_id
            len += sizeof(UInt32);
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for nack.grtt_response.tv_sec
            len += sizeof(UInt32);
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for nack.grtt_response.tv_usec
            len += sizeof(UInt32);
            EXTERNAL_ntoh(&buffer[len], sizeof(Int16));        // for nack.loss_estimate
            len += sizeof(Int16);
            len++;                                             // for nack.grtt_req_sequence
            // for nack.data
            // Unpack the concatenated Object/Repair Nacks
            char* optr = (char*)&buffer[len];
            char* nack_end = optr + (size - (Int32)len);
            while (optr < nack_end)
            {
                MdpObjectNack onack;
                memset(&onack, 0, sizeof(MdpObjectNack));
                count = 0;
                EXTERNAL_ntoh(&optr[count], sizeof(UInt32));  // for object_id
                count += sizeof(UInt32);
                EXTERNAL_ntoh(&optr[count], sizeof(Int16));   // for nack_len
                memcpy(&onack.nack_len, &optr[count], sizeof(Int16));
                count += sizeof(Int16);
                // rest is data, so increasing the count with nack_len
                onack.data = &optr[count];
                count += onack.nack_len;
                // and increasing the optr for next Object Nack
                optr += count;

                // Now Unpack the concatenated Repair Nacks
                char* rptr = onack.data;
                char* onack_end = rptr + onack.nack_len;
                MdpRepairNack rnack;
                memset(&rnack, 0, sizeof(MdpRepairNack));
                while (rptr < onack_end)
                {
                    count = 0;
                    rnack.type = (MdpRepairType) rptr[count++];

                    switch (rnack.type)
                    {
                        case MDP_REPAIR_OBJECT:
                        case MDP_REPAIR_INFO:
                            break;
                        case MDP_REPAIR_SEGMENTS:
                            rnack.nerasure = (unsigned char)rptr[count++];
                        case MDP_REPAIR_BLOCKS:
                            EXTERNAL_ntoh(&rptr[count], sizeof(UInt32));  // for offset
                            count += sizeof(UInt32);
                            EXTERNAL_ntoh(&rptr[count], sizeof(Int16));
                            memcpy(&rnack.mask_len,
                                   &rptr[count],
                                   sizeof(Int16));
                            count += sizeof(Int16);
                            // rest is mask, so increasing the count with mask_len
                            rnack.mask = &rptr[count];
                            count += rnack.mask_len;
                            break;
                        default:
                            if (MDP_DEBUG)
                            {
                                printf("MdpSwapIncomingPacketForNtoh(): "
                                       "Invalid repair nack!\n");
                            }
                            // this shouldn't happen
                    }
                    // increase the rptr for next Repair Nack
                    rptr += count;
                }
            }
            break;
        }
        case MDP_ACK:
        {
            if (MDP_DEBUG)
            {
                printf("MdpSwapIncomingPacketForNtoh(): "
                       "Receiving MDP_ACK\n");
            }
            isClientMsg = TRUE;
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for ack.server_id
            len += sizeof(UInt32);
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for ack.grtt_response.tv_sec
            len += sizeof(UInt32);
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for ack.grtt_response.tv_usec
            len += sizeof(UInt32);
            EXTERNAL_ntoh(&buffer[len], sizeof(Int16));        // for ack.loss_estimate
            len += sizeof(Int16);
            // skipping 2 bytes for ack.grtt_req_sequence and ack.type
            len += 2;
            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for ack.object_id
            len += sizeof(UInt32);
            break;
        }
        default:
        {
            if (MDP_DEBUG)
            {
                printf("MdpSwapIncomingPacketForNtoh(): "
                       "Invalid MDP message type!\n");
            }
        }
    }
}


/*
 * FUNCTION:   MdpGetSession
 * PURPOSE:    Used to verify whether MDP session exist for the
 *             desire localAddr, remoteAddr, and uniqueId. If
 *             found then return session pointer
 * PARAMETERS: node - node pointer.
 *             localAddr - specify address of the sender node.
 *             remoteAddr - specify address of the receiver.
 *             uniqueId - specify unique id for MDP.
 * RETURN:     MdpSession*.
*/
MdpSession* MdpGetSession(Node* node,
                          Address localAddr,
                          Address remoteAddr,
                          Int32 uniqueId)
{
    if (!node->appData.mdp)
    {
        return NULL;
    }

    MdpSession* theSession = NULL;
    theSession = MdpFindSessionInList(node,
                                      localAddr,
                                      remoteAddr,
                                      uniqueId);

    return theSession;
}



/*
 * NAME:        MdpGetSessionForEXataPort
 * PURPOSE:     Find session with respect to unique tuple entry for EXata
 *              incoming port
 * PARAMETERS:  node - pointer to the node which received the message.
 *              localAddr - address of the sender.
 *              remoteAddr - address of the receiver.
 *              exataPort - unique id assigned
 * RETURN:      pointer to found MdpSession in the list else NULL.
 */
MdpSession* MdpGetSessionForEXataPort(Node* node,
                                      Address localAddr,
                                      Address remoteAddr,
                                      Int32 exataPort)
{
    if (!node->appData.mdp)
    {
        return NULL;
    }

    if (!MdpIsExataIncomingPort(node, (UInt16)exataPort))
    {
        return NULL;
    }

    MdpSession* theSession = NULL;
    theSession = MdpFindSessionInList(node,
                                      localAddr,
                                      remoteAddr,
                                      exataPort);

    if (!theSession && !(MdpIsMulticastAddress(node, &remoteAddr)))
    {
        theSession = MdpFindSessionInList(node,
                                          remoteAddr,
                                          localAddr,
                                          exataPort);
    }
    return theSession;
}


/*
 * NAME:        MdpGetSessionForEXataPortOnMulticast
 * PURPOSE:     Find session with respect to unique tuple entry for EXata
 *              incoming port for multicast traffic
 * PARAMETERS:  node - pointer to the node which received the message.
 *              multicastAddr - multicast address
 *              exataPort - unique id assigned
 * RETURN:      pointer to found MdpSession in the list else NULL.
 */
MdpSession* MdpGetSessionForEXataPortOnMulticast(Node* node,
                                                 Address multicastAddr,
                                                 Int32 exataPort)
{
    if (!node->appData.mdp)
    {
        return NULL;
    }

    if (!MdpIsExataIncomingPort(node, (UInt16)exataPort))
    {
        return NULL;
    }

    MdpSession* theSession = NULL;
    theSession = MdpFindSessionInListForEXataMulticastPort(node,
                                                           multicastAddr,
                                                           exataPort);
    return theSession;
}


/*
 * FUNCTION:   MdpLayerInitForOtherPartitionNodes
 * PURPOSE:    Init the MDP layer for the member nodes in the partition in
.*             which the calling node exists.
 * PARAMETERS: node - node that received the message.
 *             nodeInput - specify nodeinput. Default value is NULL.
 *             destAddr - specify the multicast destination address.
 *                     For unicast it is considered as NULL (Default value).
 *             isUnicast - specify whether application is unicast/multicast.
 *                                Default value is FALSE.
 * RETURN:     void.
 */
void MdpLayerInitForOtherPartitionNodes(Node* firstNode,
                                       const NodeInput* nodeInput,
                                       Address* destAddr,
                                       BOOL isUnicast)
{
    if (isUnicast)
    {
        // MDP node data initialization
        // here firstNode is destnation node
        MdpInit(firstNode, nodeInput);
    }
    else
    {
        char errStr[MAX_STRING_LENGTH];
        char mcastMemberString[MAX_STRING_LENGTH];
        char mcastAddrString[MAX_STRING_LENGTH];
        Address mcastNodeAddr;
        Address mcastAddr;
        NodeId mcastMemNodeId;
        NodeId v6NodeId;
        BOOL isNodeId;
        BOOL retVal = FALSE;
        Int32 x = 0;
        NodeInput memberInput;
        Node* mcastNode;

        // Now do MDP init for the firstNode if it is a group member
        retVal = FALSE;

        IO_ReadCachedFile(ANY_NODEID,
                          ANY_ADDRESS,
                          nodeInput,
                          "MULTICAST-GROUP-FILE",
                          &retVal,
                          &memberInput);

        if (retVal == FALSE)
        {
            ERROR_ReportWarning("MULTICAST-GROUP-FILE is missing.\n");
        }
        else
        {
            for (x = 0; x < memberInput.numLines; x++)
            {
                sscanf(memberInput.inputStrings[x], "%s %s",
                                mcastMemberString, mcastAddrString);

                if (MAPPING_GetNetworkType(mcastAddrString) == NETWORK_IPV6)
                {
                    mcastAddr.networkType = NETWORK_IPV6;

                    IO_ParseNodeIdOrHostAddress(
                        mcastAddrString,
                        &mcastAddr.interfaceAddr.ipv6,
                        &v6NodeId);
                }
                else
                {
                    mcastAddr.networkType = NETWORK_IPV4;

                    IO_ParseNodeIdOrHostAddress(
                        mcastAddrString,
                        &mcastAddr.interfaceAddr.ipv4,
                        &isNodeId);
                }

               if (mcastAddr.networkType == NETWORK_IPV4)
               {
                   if (!(GetIPv4Address(mcastAddr) >=
                                                   IP_MIN_MULTICAST_ADDRESS))
                   {
                        sprintf(errStr,"MDP: multicast address is not a "
                                       "valid group address\n");
                        ERROR_ReportError(errStr);
                   }
               }
               else
               {
                    if (!IS_MULTIADDR6(GetIPv6Address(mcastAddr)))
                    {
                        sprintf(errStr,"MDP: multicast address is not a "
                                       "valid group address\n");
                        ERROR_ReportError(errStr);
                    }
                    else if (!Ipv6IsValidGetMulticastScope(
                                firstNode,
                                GetIPv6Address(mcastAddr)))
                    {
                        sprintf(errStr,"MDP: multicast address is not a "
                                       "valid group address\n");
                        ERROR_ReportError(errStr);
                    }
                }

                IO_AppParseSourceString(
                    firstNode,
                    memberInput.inputStrings[x],
                    mcastMemberString,
                    &mcastMemNodeId,
                    &mcastNodeAddr,
                    mcastAddr.networkType);


                mcastNode = MAPPING_GetNodePtrFromHash(
                                    firstNode->partitionData->nodeIdHash,
                                    mcastMemNodeId);

                if (mcastNode != NULL)
                {
                    // checking whether the node lies in the same group
                    if (Address_IsSameAddress(&mcastAddr,destAddr))
                    {
                        // MDP node data initialization
                        MdpInit(mcastNode, nodeInput);
                    }
                }
            }// for (x = 0; x < memberInput.numLines; x++)
        }
    }
}




/*
 * FUNCTION:   MdpQueueDataObject
 * PURPOSE:    Used to queue MDP data object by upper application.
 * PARAMETERS: node - node that received the message.
 *             localAddr - specify address of the sender node.
 *             remoteAddr - specify address of the receiver.
 *             uniqueId - specify unique id for MDP. For Exata this
 *                        will be considered as destport also
 *             itemSize - specify the complete item size
 *                        i.e. actual size + virtual size.
 *             payload - specify the payload for the item.
 *             virtualSize - specify the virtual size of the item
 *                           in the received message.
 *             theMsg - pointer to the received message.
 *             isFromAppForward - TRUE only when packet is queued from
 *                         APP_FORWARD application. Default value is FALSE.
 *             sourcePort - sending port of the application.
 *             dataObjectInfo - specify the data object info if any.
 *             dataInfosize - specify the data info size
 * RETURN:     void.
 */
void MdpQueueDataObject(Node* node,
                       Address localAddr,
                       Address remoteAddr,
                       Int32 uniqueId,
                       Int32 itemSize,
                       const char* payload,
                       Int32 virtualSize,
                       Message* theMsg,
                       BOOL isFromAppForward,
                       UInt16 sourcePort,
                       const char* dataObjectInfo,
                       UInt16 dataInfosize)
{
#ifdef APP_DEBUG
    printf("MdpQueDataObject(mdpUniqueId=%d, virtualSize=%d, itemSize=%d, "
           "payload=",uniqueId,virtualSize,itemSize);
    for (int i = 0; i < itemSize; i++)
        printf("%02X ",(0xFF & (unsigned)payload[i]));
    printf("\n");
    if (theMsg)
        MESSAGE_PrintMessage(theMsg);
#endif

    char errStr[MAX_STRING_LENGTH];
    MdpError err;
    MdpSession* theSession = NULL;
    char *mdpPayload = NULL;
    MdpObjectHandle tx_object;

    MdpData* mdpData = (MdpData*) node->appData.mdp;

    if (!mdpData)
    {
        sprintf(errStr, "MDP not found for node %d \n",node->nodeId);
        ERROR_ReportError(errStr);
    }

    if (isFromAppForward)
    {
         // adding 10 just to keep it unique
        uniqueId = mdpData->maxAppLines + 10 + uniqueId;
    }

    if (MdpIsExataIncomingPort(node, (UInt16)uniqueId))
    {
        theSession = MdpGetSessionForEXataPort(node,
                                               localAddr,
                                               remoteAddr,
                                               uniqueId);

        // add the sourceport in EXata port list to tackle the
        // unicast ACK, NACK, REPORT packets sent by EXata receiver by the
        // sender. This extra port addition is done for sender node only
        if ((Int16)sourcePort > -1)
        {
            MdpAddPortInExataIncomingPortList(node, sourcePort);

            // also add the session in portmap list so that the exata client
            // packets coming with this sourceport as destport retrives the
            // same session of the application. Below function will add the
            // session if its entry not exist.
            if (theSession)
            {
                MdpAddSessionInPortMapList(node, sourcePort, theSession);
            }
        }
    }
    else
    {
        theSession = MdpFindSessionInList(node,
                                      localAddr,
                                      remoteAddr,
                                      uniqueId);
    }

    if (!theSession)
    {
        sprintf(errStr, "MDP Session %d not found for "
                        "node %d \n",uniqueId, node->nodeId);
        ERROR_ReportError(errStr);
    }

    if (sourcePort > 0)
    {
        theSession->GetLocalAddr().PortSet(sourcePort);
    }

    // Opening the MDP sender
    if (!theSession->IsServerOpen())
    {
        MdpError err = theSession->OpenServer(
                                (UInt16)theSession->GetSegmentSize(),
                                (unsigned char)theSession->GetBlockSize(),
                                (unsigned char)theSession->GetNumParity(),
                                theSession->GetSessionTxBufferSize());
        if (err != MDP_ERROR_NONE)
        {
            sprintf(errStr,"Error in opening MDP sender. "
                           "(Error = %d)\n",err);
            ERROR_ReportError(errStr);
        }
    }

    mdpPayload = MESSAGE_ReturnPacket(theMsg);

    // Send mdpPayload through MDP way
    tx_object = (MdpObjectHandle)theSession->
                                        NewTxDataObject(dataObjectInfo,
                                                  dataInfosize,
                                                  mdpPayload,
                                                  itemSize + virtualSize,
                                                  &err,
                                                  (char*)theMsg,
                                                  virtualSize);

    if (tx_object == MDP_NULL_OBJECT)
    {
        if (err == MDP_ERROR_TX_QUEUE_FULL)
        {
            sprintf(errStr,"Tx queue is full. Increase the cache limit "
               "for node %d.\n",node->nodeId);
            ERROR_ReportWarning(errStr);
        }
        else if (err == MDP_ERROR_MEMORY)
        {
            sprintf(errStr,"Memory is full while queuing object "
               "for node %d.\n",node->nodeId);
            ERROR_ReportWarning(errStr);
        }
        else
        {
            sprintf(errStr,"Error in queueing tx data "
               "object for node %d. (Error = %d)\n",node->nodeId, err);
            ERROR_ReportError(errStr);
        }

        // incrementing the stats counter
        theSession->GetMdpCommonStats().numDataObjFailToQueue++;
    }
}





/*
 * FUNCTION:   MdpQueueFileObject
 * PURPOSE:    Used to queue MDP file object by the upper applications.
 * PARAMETERS: node - node that received the message.
 *             localAddr - specify address of the sender node.
 *             remoteAddr - specify address of the receiver.
 *             thePath - specify the path for the file object.
 *             fileName - specify the name of the file.
 *             uniqueId - specify unique id for MDP.
 *             sourcePort - specify sourceport of the application.
 *             theMsg - pointer to the received message.
 *             isFromAppForward - TRUE only when packet is queued from
 *                         APP_FORWARD application. Default value is FALSE.
 * RETURN:     void.
 */
void MdpQueueFileObject(Node* node,
                           Address localAddr,
                           Address remoteAddr,
                           const char* thePath,
                           char* fileName,
                           Int32 uniqueId,
                           UInt16 sourcePort,
                           Message* theMsg,
                           BOOL isFromAppForward)
{
    char errStr[MAX_STRING_LENGTH];
    MdpError err;
    MdpSession* theSession = NULL;
    MdpObjectHandle tx_object;

    MdpData* mdpData = (MdpData*) node->appData.mdp;

    if (!mdpData)
    {
        sprintf(errStr, "MDP not found for node %d \n",node->nodeId);
        ERROR_ReportError(errStr);
    }

    if (fileName == NULL)
    {
        sprintf(errStr,"For file object transmission, fileName "
                       "should not be NULL. \n");
        ERROR_ReportError(errStr);
    }

    if (MdpIsExataIncomingPort(node, (UInt16)uniqueId))
    {
        theSession = MdpGetSessionForEXataPort(node,
                                               localAddr,
                                               remoteAddr,
                                               uniqueId);
        // add the sourceport in EXata port list to tackle the
        // unicast ACK, NACK, REPORT packets sent by EXata receiver by the
        // sender. This extra port addition is done for sender node only
        if ((Int16)sourcePort > -1)
        {
            MdpAddPortInExataIncomingPortList(node, sourcePort);

            // also add the session in portmap list so that the exata client
            // packets coming with this sourceport as destport retrives the
            // same session of the application. Below function will add the
            // session if its entry not exist.
            if (theSession)
            {
                MdpAddSessionInPortMapList(node, sourcePort, theSession);
            }
        }
    }
    else
    {
        theSession = MdpFindSessionInList(node,
                                          localAddr,
                                          remoteAddr,
                                          uniqueId);
    }

    if (!theSession)
    {
        char localAddrString[MAX_STRING_LENGTH];
        char remoteAddrString[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(&remoteAddr,
                                    localAddrString);
        IO_ConvertIpAddressToString(&localAddr,
                                    remoteAddrString);

        sprintf(errStr, "MDP Session for unique id %d, "
                        "local address %s and dest address %s "
                        "not found on node %d \n",
                        uniqueId, localAddrString,
                        remoteAddrString, node->nodeId);
        ERROR_ReportError(errStr);
    }

    if ((Int16)sourcePort > -1)
    {
        theSession->GetLocalAddr().PortSet(sourcePort);
    }

    // Opening the MDP sender
    if (!theSession->IsServerOpen())
    {
        MdpError err = theSession->OpenServer(
                                (UInt16)theSession->GetSegmentSize(),
                                (unsigned char)theSession->GetBlockSize(),
                                (unsigned char)theSession->GetNumParity(),
                                theSession->GetSessionTxBufferSize());
        if (err != MDP_ERROR_NONE)
        {
            sprintf(errStr,"Error in opening MDP sender. "
                           "(Error = %d)\n",err);
            ERROR_ReportError(errStr);
        }
    }

    // Send file through MDP way
    tx_object = (MdpObjectHandle)theSession->NewTxFileObject(thePath,
                                                             fileName,
                                                             &err,
                                                             (char*)theMsg);

    if (tx_object == MDP_NULL_OBJECT)
    {
        if (err == MDP_ERROR_TX_QUEUE_FULL)
        {
            sprintf(errStr,"Tx queue is full. Increase the cache limit "
               "for node %d.\n",node->nodeId);
            ERROR_ReportWarning(errStr);
        }
        else if (err == MDP_ERROR_MEMORY)
        {
            sprintf(errStr,"Memory is full while queuing object "
               "for node %d.\n",node->nodeId);
            ERROR_ReportWarning(errStr);
        }
        else if (err == MDP_ERROR_FILE_OPEN)
        {
            sprintf(errStr,"File %s is not a valid file for queuing "
               "for node %d.\n",fileName,node->nodeId);
            ERROR_ReportWarning(errStr);
        }
        else
        {
            sprintf(errStr,"Error in queueing tx data "
               "object for node %d. (Error = %d)\n",node->nodeId, err);
            ERROR_ReportError(errStr);
        }

        // increamenting the stats counter
        theSession->GetMdpCommonStats().numFileObjFailToQueue++;
    }
}





/*
 * FUNCTION:   MdpNotifyLastDataObject
 * PURPOSE:    Used to notify MDP that last data object is sent
 * PARAMETERS: node - node that received the message.
 *             localAddr - specify address of the sender node.
 *             remoteAddr - specify address of the receiver.
 *             uniqueId - specify unique id for MDP.
 * RETURN:     void.
 */
void MdpNotifyLastDataObject(Node* node,
                           Address localAddr,
                           Address remoteAddr,
                           Int32 uniqueId)
{
    char errStr[MAX_STRING_LENGTH];
    MdpSession* theSession = NULL;

    MdpData* mdpData = (MdpData*) node->appData.mdp;

    if (!mdpData)
    {
        sprintf(errStr, "MDP not found for node %d \n",node->nodeId);
        ERROR_ReportError(errStr);
    }

    if (uniqueId == -1)
    {
        uniqueId = mdpData->maxAppLines + 10; //adding 10 just to keep it unique
    }

    if (MdpIsExataIncomingPort(node, (UInt16)uniqueId))
    {
        theSession = MdpGetSessionForEXataPort(node,
                                               localAddr,
                                               remoteAddr,
                                               uniqueId);
    }
    else
    {
        theSession = MdpFindSessionInList(node,
                                      localAddr,
                                      remoteAddr,
                                      uniqueId);
    }

    if (!theSession)
    {
        sprintf(errStr, "MDP Session %d not found for "
                        "node %d \n",uniqueId, node->nodeId);
        ERROR_ReportError(errStr);
    }

    theSession->SetLastDataObjectStatus(TRUE);
}
