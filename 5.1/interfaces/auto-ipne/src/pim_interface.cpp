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

#include "api.h"
#ifdef ADDON_DB
#include "dbapi.h"
#endif
#include "partition.h"
#include "app_util.h"
#include "external.h"
#include "external_socket.h"
#include "multicast_pim.h"
#include "auto-ipnetworkemulator.h"
#include "pim_interface.h"
#include "packet_analyzer.h"
#include "multicast_pim.h"


void PIMPacketHandler::ReformatIncomingPacket(unsigned char *packet, int pktLen)
{
    /* Get PIM Common header */
    RoutingPimCommonHeaderType* commonHeader =
        (RoutingPimCommonHeaderType*) packet;
    //commonHeader->checksum = ComputePIMChecksum(packet, pktLen);

    switch (RoutingPimCommonHeaderGetType(commonHeader->rpChType))
    {
        case ROUTING_PIM_HELLO:
        {
            char* dataPtr;
            RoutingPimHelloPacketOption* option;
            int optionLen;
            int    dataLen;

            dataLen = pktLen - sizeof(RoutingPimCommonHeaderType);
            dataPtr = ((char*) packet) + sizeof(RoutingPimCommonHeaderType);

            /* Ignore any data shorter than PIM Hello header */
            while (dataLen >= (signed) sizeof(RoutingPimHelloPacket))
            {
                /* Hold Time option */
                option = (RoutingPimHelloPacketOption*) dataPtr;
                EXTERNAL_ntoh(
                    (void *)&option->optionType,
                    sizeof(unsigned short));
                EXTERNAL_ntoh(
                    (void *)&option->optionLength,
                    sizeof(unsigned short));
                optionLen = option->optionLength;

                dataPtr += sizeof(RoutingPimHelloPacketOption);
                switch (option->optionType)
                {
                    case ROUTING_PIM_HOLD_TIME:
                    {
                        unsigned short holdTime = 0;
                        memcpy(&holdTime, dataPtr, option->optionLength);

                        EXTERNAL_ntoh((void *)&holdTime,
                                       sizeof(unsigned short));
                        memcpy(dataPtr, &holdTime, option->optionLength);

                        break;
                    }
                    case ROUTING_PIM_LAN_PRUNE_DELAY:
                    {
                        //TO BE DONE ????DISCUSS
                        break;
                    }
                    case ROUTING_PIM_DR_PRIORITY:
                    {
                        unsigned int drPriority = 0;
                        memcpy(&drPriority, dataPtr, option->optionLength);

                        EXTERNAL_ntoh((void *)&drPriority,
                                       sizeof(unsigned int));
                        memcpy(dataPtr, &drPriority, option->optionLength);
                        break;
                    }
                    case ROUTING_PIM_GEN_ID:
                    {
                        unsigned int genId = 0;
                        memcpy(&genId, dataPtr, option->optionLength);

                        EXTERNAL_ntoh((void *)&genId,
                                       sizeof(unsigned int));
                        memcpy(dataPtr, &genId, option->optionLength);

                        break;
                    }
                    default :
                    {
                        //This option is not supported
                    }
                }

                dataPtr += optionLen;
                //dataPtr += (sizeof(RoutingPimHelloPacketOption)
                //            + optionLen;

                dataLen -= (sizeof(RoutingPimHelloPacketOption)
                           + optionLen);
            }

#ifdef ASDF

                // Option Value
                /*
                EXTERNAL_ntoh(
                    (void *)&dataPtr,
                    sizeof(unsigned short));
                */
                dataPtr += sizeof(unsigned short);

                /* Generation Id option */
                option = (RoutingPimHelloPacketOption*) dataPtr;
                EXTERNAL_ntoh(
                    (void *)&option->optionType,
                    sizeof(unsigned short));
                EXTERNAL_ntoh(
                    (void *)&option->optionLength,
                    sizeof(unsigned short));
#ifdef DERIUS
                dataPtr += sizeof(RoutingPimHelloPacketOption);
                // Option Value
                EXTERNAL_ntoh(
                    (void *)&dataPtr,
                    sizeof(int));
#endif
                /*
                dataPtr += sizeof(RoutingPimHelloPacketOption);
                dataPtr += optionLen;
                dataLen -= (sizeof(RoutingPimHelloPacketOption)
                       + optionLen);
                */
#endif
            break;
        }
        case ROUTING_PIM_JOIN_PRUNE:
        {
            char* dataPtr;
            RoutingPimSmJoinPruneGroupInfo* grpInfo;
            RoutingPimEncodedSourceAddr * encodedSrcAddr;
            int NumGroup;
            int NumJoinedSrc;
            int NumPrunedSrc;

            RoutingPimSmJoinPrunePacket* joinPrunePkt =
                (RoutingPimSmJoinPrunePacket*) packet;

            //EXTERNAL_ntoh(
             //   (void *) &joinPrunePkt->upstreamNbr.unicastAddr,
              //  sizeof(NodeAddress));
            EXTERNAL_ntoh(
                (void *) &joinPrunePkt->holdTime,
                sizeof(short));

            NumGroup = joinPrunePkt->numGroups;
            grpInfo =
                (RoutingPimSmJoinPruneGroupInfo*) (joinPrunePkt + 1);

            dataPtr = (char*) grpInfo;
            while(NumGroup)
            {
                EXTERNAL_ntoh(
                    (void *)&grpInfo->encodedGrpAddr.groupAddr,
                    sizeof(NodeAddress));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numJoinedSrc,
                    sizeof(short));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numPrunedSrc,
                    sizeof(short));
                encodedSrcAddr =
                    (RoutingPimEncodedSourceAddr*)(grpInfo + 1);

                NumJoinedSrc = grpInfo->numJoinedSrc;
                NumPrunedSrc = grpInfo->numPrunedSrc;

                dataPtr += (NumJoinedSrc+NumPrunedSrc) *
                            sizeof(RoutingPimEncodedSourceAddr)
                            + sizeof(RoutingPimSmJoinPruneGroupInfo);

                while(NumJoinedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumJoinedSrc--;
                }
                while(NumPrunedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumPrunedSrc--;
                }

                //grpInfo =
                 //   (RoutingPimSmJoinPruneGroupInfo*) (grpInfo + 1);
                grpInfo =
                    (RoutingPimSmJoinPruneGroupInfo*) dataPtr;
                NumGroup--;
            }
            break;
        }

        case ROUTING_PIM_ASSERT:
        {
            char* tempPacket = (char*)packet;
            tempPacket = tempPacket + sizeof(RoutingPimCommonHeaderType);
            tempPacket = tempPacket + 4;
            EXTERNAL_ntoh(
                (void *)tempPacket,
                sizeof(NodeAddress));
            tempPacket = tempPacket + sizeof(NodeAddress);
            tempPacket = tempPacket + sizeof(RoutingPimEncodedUnicastAddr);
            EXTERNAL_ntoh(
                (void *)tempPacket,
                sizeof(UInt32));
            tempPacket = tempPacket + sizeof(UInt32);
            EXTERNAL_ntoh(
                (void *)tempPacket,
                sizeof(unsigned  int));
            break;
        }
        case ROUTING_PIM_REGISTER_STOP:
        {
            RoutingPimSmRegisterStopPacket* registerStopPkt=
                (RoutingPimSmRegisterStopPacket*) packet;
            EXTERNAL_ntoh(
                (void *)&registerStopPkt->encodedGroupAddr.groupAddr,
                sizeof(NodeAddress));
            //EXTERNAL_ntoh(
              //  (void *)&registerStopPkt->encodedSrcAddr.unicastAddr,
                //sizeof(NodeAddress));
            break;
        }
        case ROUTING_PIM_REGISTER:
        {
            RoutingPimSmRegisterPacket* registerPkt=
                (RoutingPimSmRegisterPacket*) packet;
            BOOL isNullReg=FALSE;
            isNullReg=(registerPkt->rpSmRegPkt) && (0x00000002);
            unsigned char * dataPacket = (unsigned char *)packet + sizeof(RoutingPimSmRegisterPacket);
            EXTERNAL_ntoh(
                (void *)&registerPkt->rpSmRegPkt,
                sizeof(UInt32));
            PIM_HeaderSwap(dataPacket, TRUE,isNullReg); //incoming
            break;
        }
        case ROUTING_PIM_CANDIDATE_RP:
        {
            int NumGroup;
            RoutingPimEncodedGroupAddr * grpInfo;

            RoutingPimSmCandidateRPPacket* candidateRPPkt=
                (RoutingPimSmCandidateRPPacket*) packet;
            NumGroup = candidateRPPkt->prefixCount;

            EXTERNAL_ntoh(
                (void *) &candidateRPPkt->holdtime,
                sizeof(short));
            //EXTERNAL_ntoh(
            //    (void *) &candidateRPPkt->encodedUnicastRP.unicastAddr,
            //    sizeof(NodeAddress));
            grpInfo =
                (RoutingPimEncodedGroupAddr*) (candidateRPPkt + 1);
            while(NumGroup)
            {
                EXTERNAL_ntoh(
                    (void *)&grpInfo->groupAddr,
                    sizeof(NodeAddress));
                grpInfo =
                    (RoutingPimEncodedGroupAddr*) (grpInfo + 1);
                NumGroup--;
            }

            break;
        }
        case ROUTING_PIM_BOOTSTRAP:
        {
            RoutingPimSmBootstrapPacket* bootstrapPkt =
                (RoutingPimSmBootstrapPacket *)packet;
            RoutingPimSmEncodedUnicastRPInfo  * RPInfo = NULL;

            RoutingPimSmEncodedGroupBSRInfo * grpInfo =
                (RoutingPimSmEncodedGroupBSRInfo*) (bootstrapPkt + 1);
            int rpCount = 0;
            int bsmSize = 0;
            char* dataPtr = NULL;

            EXTERNAL_ntoh(
                (void *)&bootstrapPkt->fragmentTag,
                sizeof(short));

            //NO NEED OF CHANGE HERE AS

            /*If the address is ox c0 00 04 02
            then during the incoming of packet it will come as 02 04 00 c0
            so unicastAddr[0] = 02
            unicastAddr[1] = 04
            unicastAddr[2] = 00
            unicastAddr[3] = c0
            during copy of bootstrap packet the copy will be done from char[0]
            to higher address.
            When it will get converted into NodeAddress it will become
            c0 00 04 02 which is the required ans and hence there is no need of
            byte swapping*/

            bsmSize = pktLen;

            //reaching the grpInfp part of the packet
            dataPtr = (char*)bootstrapPkt + sizeof(RoutingPimSmBootstrapPacket);
            bsmSize = bsmSize - sizeof(RoutingPimSmBootstrapPacket);

            //for each group
            while (bsmSize > 0)
            {
                grpInfo = (RoutingPimSmEncodedGroupBSRInfo*) (dataPtr);

                EXTERNAL_ntoh(
                (void *)&grpInfo->encodedGrpAddr.groupAddr,
                sizeof(NodeAddress));

                bsmSize = bsmSize - sizeof(RoutingPimSmEncodedGroupBSRInfo);
                if (bsmSize > 0)
                {
                    dataPtr = dataPtr + sizeof(RoutingPimSmEncodedGroupBSRInfo);
                }

                //for each RP present for this group range
                rpCount = grpInfo->rpCount;
                while (rpCount)
                {
                    RPInfo = (RoutingPimSmEncodedUnicastRPInfo*) (dataPtr);
                    EXTERNAL_ntoh(
                    (void *)&RPInfo->RPHoldTime,
                    sizeof(short));

                    bsmSize = bsmSize - sizeof(RoutingPimSmEncodedUnicastRPInfo);
                    if (bsmSize > 0)
                    {
                        dataPtr = dataPtr + sizeof(RoutingPimSmEncodedUnicastRPInfo);
                    }

                    rpCount--;
                }
            }
            break;
        }
        case ROUTING_PIM_GRAFT:
        {
            char* dataPtr;
            RoutingPimSmJoinPruneGroupInfo* grpInfo;
            RoutingPimEncodedSourceAddr * encodedSrcAddr;
            int NumGroup;
            int NumJoinedSrc;
            int NumPrunedSrc;

            RoutingPimSmJoinPrunePacket* joinPrunePkt =
                (RoutingPimSmJoinPrunePacket*) packet;
            //EXTERNAL_ntoh(
             //   (void *) &joinPrunePkt->upstreamNbr.unicastAddr,
              //  sizeof(NodeAddress));
            EXTERNAL_ntoh(
                (void *) &joinPrunePkt->holdTime,
                sizeof(short));

            NumGroup = joinPrunePkt->numGroups;
            grpInfo =
                (RoutingPimSmJoinPruneGroupInfo*) (joinPrunePkt + 1);

            dataPtr = (char *)grpInfo;

            while(NumGroup)
            {

                EXTERNAL_ntoh(
                    (void *)&grpInfo->encodedGrpAddr.groupAddr,
                    sizeof(NodeAddress));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numJoinedSrc,
                    sizeof(short));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numPrunedSrc,
                    sizeof(short));
                encodedSrcAddr =
                    (RoutingPimEncodedSourceAddr*)(grpInfo + 1);

                NumJoinedSrc = grpInfo->numJoinedSrc;
                NumPrunedSrc = grpInfo->numPrunedSrc;

                dataPtr += (NumJoinedSrc + NumPrunedSrc)
                            * sizeof(RoutingPimEncodedSourceAddr)
                            + sizeof(RoutingPimSmJoinPruneGroupInfo);
                while(NumJoinedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumJoinedSrc--;
                }
                while(NumPrunedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumPrunedSrc--;
                }
                grpInfo = (RoutingPimSmJoinPruneGroupInfo*) dataPtr;
                    //(RoutingPimSmJoinPruneGroupInfo*) (grpInfo + 1);
                NumGroup--;
            }
            break;
        }
        case ROUTING_PIM_GRAFT_ACK:
        {
            char* dataPtr;
            RoutingPimSmJoinPruneGroupInfo* grpInfo;
            RoutingPimEncodedSourceAddr * encodedSrcAddr;
            int NumGroup;
            int NumJoinedSrc;
            int NumPrunedSrc;

            RoutingPimSmJoinPrunePacket* joinPrunePkt =
                (RoutingPimSmJoinPrunePacket*) packet;
            //EXTERNAL_ntoh(
             //   (void *) &joinPrunePkt->upstreamNbr.unicastAddr,
              //  sizeof(NodeAddress));
            EXTERNAL_ntoh(
                (void *) &joinPrunePkt->holdTime,
                sizeof(short));

            NumGroup = joinPrunePkt->numGroups;
            grpInfo =
                (RoutingPimSmJoinPruneGroupInfo*) (joinPrunePkt + 1);

            dataPtr = (char *)grpInfo;

            while(NumGroup)
            {

                EXTERNAL_ntoh(
                    (void *)&grpInfo->encodedGrpAddr.groupAddr,
                    sizeof(NodeAddress));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numJoinedSrc,
                    sizeof(short));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numPrunedSrc,
                    sizeof(short));
                encodedSrcAddr =
                    (RoutingPimEncodedSourceAddr*)(grpInfo + 1);

                NumJoinedSrc = grpInfo->numJoinedSrc;
                NumPrunedSrc = grpInfo->numPrunedSrc;

                dataPtr += (NumJoinedSrc + NumPrunedSrc)
                            * sizeof(RoutingPimEncodedSourceAddr)
                            + sizeof(RoutingPimSmJoinPruneGroupInfo);
                while(NumJoinedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumJoinedSrc--;
                }
                while(NumPrunedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumPrunedSrc--;
                }
                grpInfo = (RoutingPimSmJoinPruneGroupInfo*) dataPtr;
                    //(RoutingPimSmJoinPruneGroupInfo*) (grpInfo + 1);
                NumGroup--;
            }
            break;
        }
        case ROUTING_PIM_STATE_REFRESH:
        {
            //The state refresh packet is not handled by QualNet
            //No need to swap the bytes
            break;
        }
        default:
        {
            char buf[MAX_STRING_LENGTH];
            sprintf(buf,
              "Unknown packet type\n");
            ERROR_ReportWarning(buf);
            return;
        }
    }
    if (RoutingPimCommonHeaderGetType(commonHeader->rpChType) == ROUTING_PIM_REGISTER )
    {
        //commonHeader->checksum = ComputePIMChecksum(packet, sizeof(RoutingPimCommonHeaderType));
    }
    else
    {
        /* checksum calculation */
        //commonHeader->checksum = ComputePIMChecksum(packet, pktLen);
    }
}

void PIMPacketHandler::ReformatOutgoingPacket(unsigned char *packet, int pktLen)
{
    /* Get PIM Common header */
    RoutingPimCommonHeaderType* commonHeader =
        (RoutingPimCommonHeaderType*) packet;
    switch (RoutingPimCommonHeaderGetType(commonHeader->rpChType))
    {
        case ROUTING_PIM_HELLO:
        {
            char* dataPtr;
            RoutingPimHelloPacketOption* option;
            int optionLen;
            int dataLen;

            dataLen = pktLen - sizeof(RoutingPimCommonHeaderType);
            dataPtr = ((char*) packet) + sizeof(RoutingPimCommonHeaderType);

            /* Ignore any data shorter than PIM Hello header */
            while (dataLen >= (signed) sizeof(RoutingPimHelloPacket))
            {
                option = (RoutingPimHelloPacketOption*) dataPtr;
                optionLen = option->optionLength;

                //EXTERNAL_ntoh(
                //    (void *)&option->optionType,
                //    sizeof(unsigned short));
                //EXTERNAL_ntoh(
                //    (void *)&option->optionLength,
                //    sizeof(unsigned short));

                dataPtr += sizeof(RoutingPimHelloPacketOption);
                switch (option->optionType)
                {
                    case ROUTING_PIM_HOLD_TIME:
                    {
                        unsigned short holdTime = 0;
                        memcpy(&holdTime, dataPtr, option->optionLength);

                        EXTERNAL_ntoh((void *)&holdTime,
                                       sizeof(unsigned short));
                        memcpy(dataPtr, &holdTime, option->optionLength);

                        break;
                    }
                    case ROUTING_PIM_LAN_PRUNE_DELAY:
                    {
                        //TO BE DONE ????DISCUSS
                        break;
                    }
                    case ROUTING_PIM_DR_PRIORITY:
                    {
                        unsigned int drPriority = 0;
                        memcpy(&drPriority, dataPtr, option->optionLength);

                        EXTERNAL_ntoh((void *)&drPriority,
                                       sizeof(unsigned int));
                        memcpy(dataPtr, &drPriority, option->optionLength);
                        break;
                    }
                    case ROUTING_PIM_GEN_ID:
                    {
                        unsigned int genId = 0;
                        memcpy(&genId, dataPtr, option->optionLength);

                        EXTERNAL_ntoh((void *)&genId,
                                       sizeof(unsigned int));
                        memcpy(dataPtr, &genId, option->optionLength);

                        break;
                    }
                    default :
                    {
                        //This option is not supported
                    }
                }

                dataPtr += optionLen;

                EXTERNAL_ntoh((void *)&option->optionType,
                               sizeof(unsigned short));
                EXTERNAL_ntoh((void *)&option->optionLength,
                               sizeof(unsigned short));
                //dataPtr += (sizeof(RoutingPimHelloPacketOption)
                //            + optionLen;

                dataLen -= (sizeof(RoutingPimHelloPacketOption)
                           + optionLen);
            }
            break;
        }
        case ROUTING_PIM_JOIN_PRUNE:
        {
            char* dataPtr;
            RoutingPimSmJoinPruneGroupInfo* grpInfo;
            RoutingPimEncodedSourceAddr * encodedSrcAddr;
            int NumGroup;
            int NumJoinedSrc;
            int NumPrunedSrc;

            RoutingPimSmJoinPrunePacket* joinPrunePkt =
                (RoutingPimSmJoinPrunePacket*) packet;
            //EXTERNAL_ntoh(
             //   (void *) &joinPrunePkt->upstreamNbr.unicastAddr,
              //  sizeof(NodeAddress));
            EXTERNAL_ntoh(
                (void *) &joinPrunePkt->holdTime,
                sizeof(short));

            NumGroup = joinPrunePkt->numGroups;
            grpInfo =
                (RoutingPimSmJoinPruneGroupInfo*) (joinPrunePkt + 1);

            dataPtr = (char *)grpInfo;

            while(NumGroup)
            {
                NumJoinedSrc = grpInfo->numJoinedSrc;
                NumPrunedSrc = grpInfo->numPrunedSrc;
                EXTERNAL_ntoh(
                    (void *)&grpInfo->encodedGrpAddr.groupAddr,
                    sizeof(NodeAddress));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numJoinedSrc,
                    sizeof(short));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numPrunedSrc,
                    sizeof(short));
                encodedSrcAddr =
                    (RoutingPimEncodedSourceAddr*)(grpInfo + 1);
                dataPtr += (NumJoinedSrc + NumPrunedSrc)
                            * sizeof(RoutingPimEncodedSourceAddr)
                            + sizeof(RoutingPimSmJoinPruneGroupInfo);
                while(NumJoinedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumJoinedSrc--;
                }
                while(NumPrunedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumPrunedSrc--;
                }
                grpInfo = (RoutingPimSmJoinPruneGroupInfo*) dataPtr;
                    //(RoutingPimSmJoinPruneGroupInfo*) (grpInfo + 1);
                NumGroup--;
            }
            break;
        }
        case ROUTING_PIM_ASSERT:
        {
            char* tempPacket = (char*)packet;
            tempPacket = tempPacket + sizeof(RoutingPimCommonHeaderType);
            tempPacket = tempPacket + 4;
            EXTERNAL_ntoh(
                (void *)tempPacket,
                sizeof(NodeAddress));
            tempPacket = tempPacket + sizeof(NodeAddress);
            tempPacket = tempPacket + 6;
            EXTERNAL_ntoh(
                (void *)tempPacket,
                sizeof(UInt32));
            tempPacket = tempPacket + sizeof(UInt32);
            EXTERNAL_ntoh(
                (void *)tempPacket,
                sizeof(unsigned  int));
            break;
        }
        case ROUTING_PIM_REGISTER_STOP:
        {
            RoutingPimSmRegisterStopPacket* registerStopPkt=
                (RoutingPimSmRegisterStopPacket*) packet;
            EXTERNAL_ntoh(
                (void *)&registerStopPkt->encodedGroupAddr.groupAddr,
                sizeof(NodeAddress));
            //EXTERNAL_ntoh(
            //    (void *)&registerStopPkt->encodedSrcAddr.unicastAddr,
            //    sizeof(NodeAddress));
            break;
        }
        case ROUTING_PIM_REGISTER:
        {
            RoutingPimSmRegisterPacket* registerPkt=
                (RoutingPimSmRegisterPacket*) packet;
            BOOL isNullRegister = FALSE;

            isNullRegister=(registerPkt->rpSmRegPkt) && 0x40000000;

            //printf ("nullRegister is %d\n",isNullRegister);
            unsigned char * dataPacket = (unsigned char *)packet + sizeof(RoutingPimSmRegisterPacket);
            EXTERNAL_ntoh(
                (void *)&registerPkt->rpSmRegPkt,
                sizeof(UInt32));
                PIM_HeaderSwap(dataPacket, FALSE,isNullRegister); //outgoing
            break;
        }
        case ROUTING_PIM_CANDIDATE_RP:
        {
            int NumGroup;
            RoutingPimEncodedGroupAddr * grpInfo;

            RoutingPimSmCandidateRPPacket* candidateRPPkt=
                (RoutingPimSmCandidateRPPacket*) packet;
            NumGroup = candidateRPPkt->prefixCount;

            EXTERNAL_ntoh(
                (void *) &candidateRPPkt->holdtime,
                sizeof(short));
            //EXTERNAL_ntoh(
            //    (void *) &candidateRPPkt->encodedUnicastRP.unicastAddr,
            //    sizeof(NodeAddress));
            grpInfo =
                (RoutingPimEncodedGroupAddr*) (candidateRPPkt + 1);
            while(NumGroup)
            {
                EXTERNAL_ntoh(
                    (void *)&grpInfo->groupAddr,
                    sizeof(NodeAddress));
                grpInfo =
                    (RoutingPimEncodedGroupAddr*) (grpInfo + 1);
                NumGroup--;
            }

            break;
        }
        case ROUTING_PIM_BOOTSTRAP:
        {
            RoutingPimSmBootstrapPacket* bootstrapPkt =
                (RoutingPimSmBootstrapPacket *)packet;
            RoutingPimSmEncodedGroupBSRInfo * grpInfo =
                (RoutingPimSmEncodedGroupBSRInfo*) (bootstrapPkt + 1);

            RoutingPimSmEncodedUnicastRPInfo  * RPInfo = NULL;
            int rpCount = 0;
            int bsmSize = 0;
            char* dataPtr = NULL;

            EXTERNAL_ntoh(
                (void *)&bootstrapPkt->fragmentTag,
                sizeof(short));


            bsmSize = pktLen;

            //reaching the grpInfp part of the packet
            dataPtr = (char*)bootstrapPkt + sizeof(RoutingPimSmBootstrapPacket);
            bsmSize = bsmSize - sizeof(RoutingPimSmBootstrapPacket);

            //for each group
            while (bsmSize > 0)
            {
                grpInfo = (RoutingPimSmEncodedGroupBSRInfo*) (dataPtr);

                EXTERNAL_ntoh(
                (void *)&grpInfo->encodedGrpAddr.groupAddr,
                sizeof(NodeAddress));

                bsmSize = bsmSize - sizeof(RoutingPimSmEncodedGroupBSRInfo);
                if (bsmSize > 0)
                {
                    dataPtr = dataPtr + sizeof(RoutingPimSmEncodedGroupBSRInfo);
                }

                //for each RP present for this group range
                rpCount = grpInfo->rpCount;
                while (rpCount)
                {
                    RPInfo = (RoutingPimSmEncodedUnicastRPInfo*) (dataPtr);
                    EXTERNAL_ntoh(
                    (void *)&RPInfo->RPHoldTime,
                    sizeof(short));

                    bsmSize = bsmSize - sizeof(RoutingPimSmEncodedUnicastRPInfo);
                    if (bsmSize > 0)
                    {
                        dataPtr = dataPtr + sizeof(RoutingPimSmEncodedUnicastRPInfo);
                    }

                    rpCount--;
                }
            }
            break;
        }
        case ROUTING_PIM_GRAFT:
        {
            char* dataPtr;
            RoutingPimSmJoinPruneGroupInfo* grpInfo;
            RoutingPimEncodedSourceAddr * encodedSrcAddr;
            int NumGroup;
            int NumJoinedSrc;
            int NumPrunedSrc;

            RoutingPimSmJoinPrunePacket* joinPrunePkt =
                (RoutingPimSmJoinPrunePacket*) packet;
            //EXTERNAL_ntoh(
             //   (void *) &joinPrunePkt->upstreamNbr.unicastAddr,
              //  sizeof(NodeAddress));
            EXTERNAL_ntoh(
                (void *) &joinPrunePkt->holdTime,
                sizeof(short));

            NumGroup = joinPrunePkt->numGroups;
            grpInfo =
                (RoutingPimSmJoinPruneGroupInfo*) (joinPrunePkt + 1);

            dataPtr = (char *)grpInfo;

            while(NumGroup)
            {
                NumJoinedSrc = grpInfo->numJoinedSrc;
                NumPrunedSrc = grpInfo->numPrunedSrc;
                EXTERNAL_ntoh(
                    (void *)&grpInfo->encodedGrpAddr.groupAddr,
                    sizeof(NodeAddress));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numJoinedSrc,
                    sizeof(short));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numPrunedSrc,
                    sizeof(short));
                encodedSrcAddr =
                    (RoutingPimEncodedSourceAddr*)(grpInfo + 1);
                dataPtr += (NumJoinedSrc + NumPrunedSrc)
                            * sizeof(RoutingPimEncodedSourceAddr)
                            + sizeof(RoutingPimSmJoinPruneGroupInfo);
                while(NumJoinedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumJoinedSrc--;
                }
                while(NumPrunedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumPrunedSrc--;
                }
                grpInfo = (RoutingPimSmJoinPruneGroupInfo*) dataPtr;
                    //(RoutingPimSmJoinPruneGroupInfo*) (grpInfo + 1);
                NumGroup--;
            }
            break;
        }
        case ROUTING_PIM_GRAFT_ACK:
        {
            char* dataPtr;
            RoutingPimSmJoinPruneGroupInfo* grpInfo;
            RoutingPimEncodedSourceAddr * encodedSrcAddr;
            int NumGroup;
            int NumJoinedSrc;
            int NumPrunedSrc;

            RoutingPimSmJoinPrunePacket* joinPrunePkt =
                (RoutingPimSmJoinPrunePacket*) packet;
            //EXTERNAL_ntoh(
             //   (void *) &joinPrunePkt->upstreamNbr.unicastAddr,
              //  sizeof(NodeAddress));
            EXTERNAL_ntoh(
                (void *) &joinPrunePkt->holdTime,
                sizeof(short));

            NumGroup = joinPrunePkt->numGroups;
            grpInfo =
                (RoutingPimSmJoinPruneGroupInfo*) (joinPrunePkt + 1);

            dataPtr = (char *)grpInfo;

            while(NumGroup)
            {
                NumJoinedSrc = grpInfo->numJoinedSrc;
                NumPrunedSrc = grpInfo->numPrunedSrc;
                EXTERNAL_ntoh(
                    (void *)&grpInfo->encodedGrpAddr.groupAddr,
                    sizeof(NodeAddress));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numJoinedSrc,
                    sizeof(short));
                EXTERNAL_ntoh(
                    (void *)&grpInfo->numPrunedSrc,
                    sizeof(short));
                encodedSrcAddr =
                    (RoutingPimEncodedSourceAddr*)(grpInfo + 1);
                dataPtr += (NumJoinedSrc + NumPrunedSrc)
                            * sizeof(RoutingPimEncodedSourceAddr)
                            + sizeof(RoutingPimSmJoinPruneGroupInfo);
                while(NumJoinedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumJoinedSrc--;
                }
                while(NumPrunedSrc)
                {
                    EXTERNAL_ntoh(
                        (void *)&encodedSrcAddr->sourceAddr,
                        sizeof(NodeAddress));

                    encodedSrcAddr =
                        (RoutingPimEncodedSourceAddr*)(encodedSrcAddr + 1);
                    NumPrunedSrc--;
                }
                grpInfo = (RoutingPimSmJoinPruneGroupInfo*) dataPtr;
                    //(RoutingPimSmJoinPruneGroupInfo*) (grpInfo + 1);
                NumGroup--;
            }
            break;
        }
        case ROUTING_PIM_STATE_REFRESH:
        {
            //The state refresh packet is not handled by QualNet
            //No need to swap the bytes
            break;
        }
        default:
        {
            printf("Unknown packet type %d\n", (RoutingPimCommonHeaderGetType(commonHeader->rpChType)));
            fflush(stdout);
        }
    }
    if (RoutingPimCommonHeaderGetType(commonHeader->rpChType) == ROUTING_PIM_REGISTER )
    {
        commonHeader->checksum = ComputePIMChecksum(packet, sizeof(RoutingPimSmRegisterPacket));
    }
    else
    {
        /* checksum calculation */
        commonHeader->checksum =0;
        commonHeader->checksum = ComputePIMChecksum(packet, pktLen);

        //if (RoutingPimCommonHeaderGetType(commonHeader->rpChType) == ROUTING_PIM_JOIN_PRUNE) //TBR
        // {
        //    EXTERNAL_ntoh(
        //                 (void *)&commonHeader->checksum,
        //                 sizeof(short));
        //}
    }
}


UInt16 PIMPacketHandler::ComputePIMChecksum(
    UInt8* packet,
    int packetLength)
{
    BOOL odd;
    UInt16* paddedPacket;
    int sum;
    int i;

    // If the packet is an odd length, pad it with a zero
    odd = packetLength & 0x1;
    if (odd)
    {
        packetLength++;
        paddedPacket = (UInt16*) MEM_malloc(packetLength);
        paddedPacket[packetLength/2 - 1] = 0;
        memcpy(paddedPacket, packet, packetLength - 1);
    }
    else
    {
        paddedPacket = (UInt16*) packet;
    }

    // Compute the checksum
    sum = 0;
    for (i = 0; i < packetLength / 2; i++)
    {
        sum += paddedPacket[i];
    }
    // Carry the 1's
    while ((0xffff & (sum >> 16)) > 0)
    {
        sum = (sum & 0xFFFF) + ((sum >> 16) & 0xffff);
    }

    // Free memory of padded packet
    if (odd)
    {
        MEM_free(paddedPacket);
    }

    // Return the checksum
    return ~((UInt16) sum);
}
